#           _          _
#        __| |____ ___| |__
#       / _  |__  / __| '_ \
#      | (_| |(_| \__ \ | | |
#       \__,_\__,_|___/_| |_(_)
#       T  R  A  I  N  I  N  G

# Script:          New-X509v3Certificate.ps1

# Originally by:   Adam Conkle - Microsoft Corporation
# Originally at:   http://social.technet.microsoft.com/wiki/contents/articles/4714.how-to-generate-a-self-signed-certificate-using-powershell.aspx

# Adopted by:      Paul Wojcicki-Jarocki - Paul Dash (paul@dash.training)
# Adopted because: * added more options for intended usage (EKU) and Subject fields
#                  * commented throughout
#                  * change to more secure sha256
#                  * certificate validity period is corrected
#                  * generated certificate is added to correct stores
#                  * added export of .CER file to user-defined path
#                  * added checks for existing certificates and successful export/import
#                  * rewritten on the .NET CertificateRequest class and split into functions
#                  * scenario, field, OID and algorithm profiles moved to New-X509v3Certificate.Data.psd1

# Run the script for the interactive wizard, or dot-source it to use the functions:
#   New-X509CertificateRequest -> New-X509Certificate -> Export-X509Certificate -> Install-X509Certificate
#   Convert-X509CertificateEncoding converts certificate data between DER and Base64.

#requires -Version 5.1

using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates

# TODO: convert to a module (manifest, Public/Private folders, Pester tests).
# TODO: expose provider/HSM selection and protected PFX export as separate, explicit workflows.
# TODO: add CSR serialization once the minimum supported .NET runtime has a uniform API.


#region Private functions (camelCase names; not intended to be called from outside this script)

<#
.SYNOPSIS
Returns the settings from the external data file, reading it only once.
#>
function getSettings {
    # Reading an undefined variable directly fails when the caller enabled StrictMode.
    $cachedSettings = Get-Variable -Name settings -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if (-not $cachedSettings) {
        $path = Join-Path -Path $PSScriptRoot -ChildPath 'New-X509v3Certificate.Data.psd1'
        if (-not (Test-Path -Path $path -PathType Leaf)) {
            throw "Data file not found: $path"
        }
        $cachedSettings = Import-PowerShellDataFile -Path $path
        if (-not $cachedSettings.Scenarios -or -not $cachedSettings.Algorithms -or -not $cachedSettings.Oids) {
            throw "The certificate data file does not match the required schema: $path"
        }
        $script:settings = $cachedSettings
    }
    $cachedSettings
}

<#
.SYNOPSIS
Prompts until the answer is one of the valid choices; returns it in upper case.
#>
function readChoice {
    param(
        [Parameter(Mandatory)] [string]   $Prompt,
        [Parameter(Mandatory)] [AllowEmptyString()] [string[]] $ValidChoices
    )
    while ($true) {
        $answer = (Read-Host -Prompt $Prompt).Trim().ToUpper()
        if ($answer -in $ValidChoices) { return $answer }
        Write-Warning "Unsupported selection. Choose one of: $($ValidChoices -join ', ')."
    }
}

<#
.SYNOPSIS
Builds the Subject distinguished name, escaping characters that are special in a DN.
#>
function convertToDistinguishedName {
    param(
        [string] $CommonName,
        [string] $Email,
        [hashtable] $Subject,
        [switch] $AllowEmpty
    )
    if ($AllowEmpty -and -not $CommonName -and -not $Email -and (-not $Subject -or $Subject.Count -eq 0)) {
        return [X500DistinguishedName]::new([byte[]](0x30, 0x00))
    }
    if (-not $CommonName -and (-not $Subject -or -not $Subject.ContainsKey('CN'))) {
        throw 'A CommonName (CN) is required unless the selected profile permits an empty Subject.'
    }
    $specialCharacters = '([,+"\\<>;=])'
    $parts = [System.Collections.Generic.List[string]]::new()
    $values = @{}
    $attributeDefinitions = (getSettings).SubjectAttributes
    if ($Subject) {
        foreach ($key in $Subject.Keys) {
            $definition = $attributeDefinitions | Where-Object { $_['Name'] -eq $key -or $_['ShortName'] -eq $key } | Select-Object -First 1
            if (-not $definition) { throw "Unsupported Subject attribute '$key'." }
            $values[$definition['ShortName']] = [string]$Subject[$key]
        }
    }
    if ($CommonName) { $values.CN = $CommonName }
    if ($Email) { $values.E = $Email }
    if ($values.C -and $values.C -notmatch '^[A-Za-z]{2}$') { throw 'Country (C) must be a two-letter code.' }
    foreach ($attribute in @($attributeDefinitions | Sort-Object { $_['Frequency'] } | ForEach-Object { $_['ShortName'] })) {
        if ($values[$attribute]) { $parts.Add("$attribute=" + ($values[$attribute] -replace $specialCharacters, '\$1')) }
    }
    [X500DistinguishedName]::new(($parts -join ', '))
}

<#
.SYNOPSIS
Maps the User/Computer answer to a store location and the key storage flags for it.
#>
function getStoreContext {
    param(
        [Parameter(Mandatory)] [ValidateSet('User', 'Computer')] [string] $Context,
        [switch] $Exportable
    )

    $flags = [X509KeyStorageFlags]::PersistKeySet
    if ($Exportable) { $flags = $flags -bor [X509KeyStorageFlags]::Exportable }
    if ($Context -eq 'User') {
        $location = [StoreLocation]::CurrentUser
    } else {
        $location = [StoreLocation]::LocalMachine
        $flags    = $flags -bor [X509KeyStorageFlags]::MachineKeySet
    }
    [pscustomobject]@{ Location = $location; KeyFlags = $flags }
}

<#
.SYNOPSIS
Returns the Context and StoreName for the current location when it is on the Cert:\ drive, otherwise $null.
#>
function getCurrentCertificateStore {
    $current = Get-Location
    if ($current.Provider.Name -ne 'Certificate') { return }

    $segments = @($current.ProviderPath -split '\\' | Where-Object { $_ })
    $context  = switch ($segments[0]) {
        'CurrentUser' { 'User' }
        'LocalMachine' { 'Computer' }
        default { return }
    }
    $storeName = if ($segments.Count -gt 1) { $segments[1] }
    $thumbprint = if ($segments.Count -gt 2) { $segments[2] }
    [pscustomobject]@{ Context = $context; StoreName = $storeName; Thumbprint = $thumbprint }
}

<#
.SYNOPSIS
Opens a certificate store. The caller must close it.
#>
function openStore {
    param(
        [Parameter(Mandatory)] [string]        $StoreName,
        [Parameter(Mandatory)] [StoreLocation] $Location,
        [OpenFlags] $Flags = [OpenFlags]::ReadOnly
    )
    $store = [X509Store]::new($StoreName, $Location)
    $store.Open($Flags)
    $store
}

<#
.SYNOPSIS
Tests whether the personal store already holds a certificate with this exact common name.
#>
function testExistingCertificate {
    param(
        [Parameter(Mandatory)] [string]        $CommonName,
        [Parameter(Mandatory)] [StoreLocation] $Location
    )
    $store = openStore -StoreName 'My' -Location $Location
    try {
        $pattern = "(^|, )CN=$([regex]::Escape($CommonName))(,|$)"
        [bool]($store.Certificates | Where-Object { $_.Subject -match $pattern })
    } finally {
        $store.Close()
    }
}

<#
.SYNOPSIS
Returns the certificate with the given thumbprint from a store, or $null.
#>
function getStoreCertificate {
    param(
        [Parameter(Mandatory)] [string]        $Thumbprint,
        [Parameter(Mandatory)] [StoreLocation] $Location,
        [string] $StoreName = 'My'
    )
    $store = openStore -StoreName $StoreName -Location $Location
    try {
        $found = $store.Certificates.Find([X509FindType]::FindByThumbprint, $Thumbprint, $false)
        if ($found.Count -gt 0) { $found[0] }
    } finally {
        $store.Close()
    }
}

<#
.SYNOPSIS
Adds a certificate to a store.
#>
function addCertificateToStore {
    param(
        [Parameter(Mandatory)] [X509Certificate2] $Certificate,
        [Parameter(Mandatory)] [string]           $StoreName,
        [Parameter(Mandatory)] [StoreLocation]    $Location
    )
    # OpenExistingOnly stops a mistyped store name from creating a new store.
    $store = openStore -StoreName $StoreName -Location $Location -Flags 'ReadWrite, OpenExistingOnly'
    try {
        $store.Add($Certificate)
    } finally {
        $store.Close()
    }
}

<#
.SYNOPSIS
Saves a certificate's public data to a new DER or Base64 file without overwriting an existing file.
#>
function saveCertificateToFile {
    param(
        [Parameter(Mandatory)] [X509Certificate2] $Certificate,
        [Parameter(Mandatory)] [string]           $Path,
        [Parameter(Mandatory)] [ValidateSet('DER', 'Base64')] [string] $Format
    )

    $encoded = Convert-X509CertificateEncoding -InputObject $Certificate.RawData -OutputFormat $Format
    $fileStream = $null
    try {
        $fileStream = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        if ($Format -eq 'DER') {
            $fileStream.Write($encoded, 0, $encoded.Length)
        } else {
            $bytes = [Text.Encoding]::ASCII.GetBytes($encoded)
            $fileStream.Write($bytes, 0, $bytes.Length)
        }
    } finally {
        if ($fileStream) { $fileStream.Dispose() }
    }
}

<#
.SYNOPSIS
Shows the EKU menu and returns the chosen OIDs (without duplicates) as a List[string].
#>
function getScenario {
    param([Parameter(Mandatory)] [string] $Name)
    $scenario = (getSettings).Scenarios | Where-Object { $_.Key -eq $Name } | Select-Object -First 1
    if (-not $scenario) { throw "Unknown certificate scenario '$Name'." }
    $scenario
}

function resolveEkuOids {
    param([string[]] $NameOrOid)
    $ekuTable = (getSettings).Oids.Eku
    foreach ($value in @($NameOrOid)) {
        if ($value -match '^\d+(\.\d+)+$') { $value; continue }
        if (-not $ekuTable.ContainsKey($value)) { throw "Unknown EKU name or OID '$value'." }
        $ekuTable[$value]
    }
}

function newCertificateKey {
    param([string] $Algorithm, [int] $KeySize, [string] $Curve)
    $definition = (getSettings).Algorithms | Where-Object Name -eq $Algorithm | Select-Object -First 1
    if (-not $definition) { throw "Unknown public-key algorithm '$Algorithm'." }
    if (-not $definition.Implemented) { throw "Algorithm '$Algorithm' is recorded in the data file but is not implemented. $($definition.Note)" }
    if ($Algorithm -eq 'RSA') {
        if ($KeySize -notin $definition.KeySizes) { throw "RSA key size must be one of: $($definition.KeySizes -join ', ')." }
        return [RSA]::Create($KeySize)
    }
    if ($Algorithm -eq 'ECDSA') {
        if ($Curve -notin $definition.Curves) { throw "ECDSA curve must be one of: $($definition.Curves -join ', ')." }
        $namedCurve = switch ($Curve) {
            P256 { [ECCurve+NamedCurves]::nistP256 }
            P384 { [ECCurve+NamedCurves]::nistP384 }
            P521 { [ECCurve+NamedCurves]::nistP521 }
        }
        return [ECDsa]::Create($namedCurve)
    }
    throw "Algorithm '$Algorithm' has no key factory."
}

function convertToKeyUsageFlags {
    param([string[]] $KeyUsage)
    $known = (getSettings).KeyUsages
    [int]$bits = 0
    foreach ($name in @($KeyUsage)) {
        $item = $known | Where-Object Name -eq $name | Select-Object -First 1
        if (-not $item) { throw "Unknown Key Usage '$name'." }
        $bits = $bits -bor [int]$item.Value
    }
    if (($KeyUsage -contains 'EncipherOnly' -or $KeyUsage -contains 'DecipherOnly') -and $KeyUsage -notcontains 'KeyAgreement') {
        throw 'EncipherOnly and DecipherOnly require KeyAgreement.'
    }
    [X509KeyUsageFlags]$bits
}

function convertFromHexString {
    param([Parameter(Mandatory)] [string] $Hex)
    if ($Hex.Length % 2) { throw 'Hexadecimal input must contain an even number of characters.' }
    $bytes = [byte[]]::new($Hex.Length / 2)
    for ($index = 0; $index -lt $bytes.Length; $index++) { $bytes[$index] = [Convert]::ToByte($Hex.Substring($index * 2, 2), 16) }
    ,$bytes
}

function convertToDerLength {
    param([Parameter(Mandatory)] [int] $Length)
    if ($Length -lt 0) { throw 'DER length cannot be negative.' }
    if ($Length -lt 128) { return ,[byte[]]$Length }
    $octets = [System.Collections.Generic.List[byte]]::new()
    while ($Length -gt 0) { $octets.Insert(0, [byte]($Length -band 0xff)); $Length = $Length -shr 8 }
    ,[byte[]](@([byte](0x80 -bor $octets.Count)) + $octets.ToArray())
}

function newDerValue {
    param([Parameter(Mandatory)] [byte] $Tag, [byte[]] $Content = @())
    ,[byte[]](@($Tag) + (convertToDerLength $Content.Length) + $Content)
}

function newDerObjectIdentifier {
    param([Parameter(Mandatory)] [string] $Oid)
    $arcs = @($Oid -split '\.' | ForEach-Object { [uint64]$_ })
    if ($arcs.Count -lt 2 -or $arcs[0] -gt 2 -or ($arcs[0] -lt 2 -and $arcs[1] -gt 39)) { throw "Invalid OID '$Oid'." }
    $content = [System.Collections.Generic.List[byte]]::new()
    $values = @(([uint64](40 * $arcs[0] + $arcs[1]))) + @($arcs | Select-Object -Skip 2)
    foreach ($value in $values) {
        $encoded = [System.Collections.Generic.List[byte]]::new()
        $current = [uint64]$value
        $encoded.Insert(0, [byte]($current -band 0x7f))
        $current = $current -shr 7
        while ($current -gt 0) { $encoded.Insert(0, [byte](0x80 -bor ($current -band 0x7f))); $current = $current -shr 7 }
        $content.AddRange($encoded)
    }
    newDerValue -Tag 0x06 -Content $content.ToArray()
}

function newUriGeneralName {
    param([Parameter(Mandatory)] [string] $Uri)
    $parsed = $null
    if (-not [System.Uri]::TryCreate($Uri, [UriKind]::Absolute, [ref]$parsed)) { throw "Invalid absolute URI '$Uri'." }
    if ($Uri.ToCharArray() | Where-Object { [int]$_ -gt 127 }) { throw 'X.509 URI values must contain IA5/ASCII characters only.' }
    newDerValue -Tag 0x86 -Content ([Text.Encoding]::ASCII.GetBytes($Uri))
}

function newInfrastructureExtensions {
    param(
        [string[]] $CaIssuerUri, [string[]] $OcspUri, [string[]] $CrlDistributionPointUri,
        [string[]] $CertificatePolicyOid, [switch] $TlsMustStaple
    )
    $settings = getSettings
    $result = [System.Collections.Generic.List[X509Extension]]::new()
    $accessDescriptions = [System.Collections.Generic.List[byte]]::new()
    foreach ($item in @($OcspUri) | Where-Object { $_ }) {
        $entry = [byte[]]((newDerObjectIdentifier $settings.Oids.AccessMethod.Ocsp) + (newUriGeneralName $item))
        $accessDescriptions.AddRange((newDerValue -Tag 0x30 -Content $entry))
    }
    foreach ($item in @($CaIssuerUri) | Where-Object { $_ }) {
        $entry = [byte[]]((newDerObjectIdentifier $settings.Oids.AccessMethod.CaIssuers) + (newUriGeneralName $item))
        $accessDescriptions.AddRange((newDerValue -Tag 0x30 -Content $entry))
    }
    if ($accessDescriptions.Count) {
        $result.Add([X509Extension]::new([Oid]::new($settings.Oids.Extensions.AuthorityInfoAccess), (newDerValue -Tag 0x30 -Content $accessDescriptions.ToArray()), $false))
    }
    if ($CrlDistributionPointUri) {
        $points = [System.Collections.Generic.List[byte]]::new()
        foreach ($item in $CrlDistributionPointUri | Where-Object { $_ }) {
            $fullName = newDerValue -Tag 0xA0 -Content (newUriGeneralName $item)
            $distributionPoint = newDerValue -Tag 0xA0 -Content $fullName
            $points.AddRange((newDerValue -Tag 0x30 -Content $distributionPoint))
        }
        if ($points.Count) { $result.Add([X509Extension]::new([Oid]::new($settings.Oids.Extensions.CrlDistributionPoints), (newDerValue -Tag 0x30 -Content $points.ToArray()), $false)) }
    }
    if ($CertificatePolicyOid) {
        $policies = [System.Collections.Generic.List[byte]]::new()
        foreach ($item in $CertificatePolicyOid | Where-Object { $_ }) { $policies.AddRange((newDerValue -Tag 0x30 -Content (newDerObjectIdentifier $item))) }
        if ($policies.Count) { $result.Add([X509Extension]::new([Oid]::new($settings.Oids.Extensions.CertificatePolicies), (newDerValue -Tag 0x30 -Content $policies.ToArray()), $false)) }
    }
    if ($TlsMustStaple) {
        $result.Add([X509Extension]::new([Oid]::new($settings.Oids.Extensions.TlsFeature), [byte[]](0x30,0x03,0x02,0x01,0x05), $false))
    }
    $result.ToArray()
}

function addSubjectAlternativeName {
    param(
        [Parameter(Mandatory)] [CertificateRequest] $Request,
        [string[]] $DnsName, [string[]] $IpAddress, [string[]] $Uri,
        [string[]] $EmailSan, [string[]] $Upn, [switch] $Critical
    )
    $values = @($DnsName) + @($IpAddress) + @($Uri) + @($EmailSan) + @($Upn) | Where-Object { $_ }
    if (-not $values) { return }
    $builder = [SubjectAlternativeNameBuilder]::new()
    foreach ($value in @($DnsName) | Where-Object { $_ }) { $builder.AddDnsName($value) }
    foreach ($value in @($IpAddress) | Where-Object { $_ }) {
        $address = $null
        if (-not [System.Net.IPAddress]::TryParse($value, [ref]$address)) { throw "Invalid SAN IP address '$value'." }
        $builder.AddIpAddress($address)
    }
    foreach ($value in @($Uri) | Where-Object { $_ }) {
        $parsed = $null
        if (-not [Uri]::TryCreate($value, [UriKind]::Absolute, [ref]$parsed)) { throw "Invalid SAN URI '$value'." }
        $builder.AddUri($parsed)
    }
    foreach ($value in @($EmailSan) | Where-Object { $_ }) { $builder.AddEmailAddress($value) }
    foreach ($value in @($Upn) | Where-Object { $_ }) { $builder.AddUserPrincipalName($value) }
    $Request.CertificateExtensions.Add($builder.Build([bool]$Critical))
}

function getSubjectKeyIdentifierBytes {
    param([Parameter(Mandatory)] [CertificateRequest] $Request)
    $ski = [X509SubjectKeyIdentifierExtension]::new($Request.PublicKey, $false)
    convertFromHexString $ski.SubjectKeyIdentifier
}

function newAuthorityKeyIdentifierExtension {
    param([Parameter(Mandatory)] [byte[]] $KeyIdentifier)
    if ($KeyIdentifier.Length -gt 127) { throw 'Authority Key Identifier is unexpectedly long.' }
    $raw = [byte[]](0x30, ($KeyIdentifier.Length + 2), 0x80, $KeyIdentifier.Length) + $KeyIdentifier
    [X509Extension]::new([Oid]::new((getSettings).Oids.Extensions.AuthorityKeyIdentifier), $raw, $false)
}

function getCertificateKeyIdentifier {
    param([Parameter(Mandatory)] [X509Certificate2] $Certificate)
    $extension = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq (getSettings).Oids.Extensions.SubjectKeyIdentifier } | Select-Object -First 1
    if ($extension) {
        $ski = [X509SubjectKeyIdentifierExtension]::new($extension, $extension.Critical)
        return ,(convertFromHexString $ski.SubjectKeyIdentifier)
    }
    $generated = [X509SubjectKeyIdentifierExtension]::new($Certificate.PublicKey, $false)
    ,(convertFromHexString $generated.SubjectKeyIdentifier)
}

function addRequestExtensions {
    param(
        [Parameter(Mandatory)] [CertificateRequest] $Request,
        [string[]] $KeyUsage, [string[]] $EkuOid,
        [bool] $IsCA, [Nullable[int]] $PathLength,
        [bool] $KeyUsageCritical = $true, [bool] $EkuCritical = $false,
        [bool] $AddSki = $true, [bool] $OcspNoCheck = $false,
        [X509Extension[]] $AdditionalExtension
    )
    $hasPathLength = $null -ne $PathLength
    if (-not $IsCA -and $hasPathLength) { throw 'PathLength is valid only for a CA certificate.' }
    $Request.CertificateExtensions.Add([X509BasicConstraintsExtension]::new($IsCA, $hasPathLength, $(if ($hasPathLength) { $PathLength.Value } else { 0 }), $IsCA))
    if ($KeyUsage) { $Request.CertificateExtensions.Add([X509KeyUsageExtension]::new((convertToKeyUsageFlags $KeyUsage), $KeyUsageCritical)) }
    if ($EkuOid) {
        $oids = [OidCollection]::new()
        foreach ($oid in $EkuOid | Select-Object -Unique) { [void]$oids.Add([Oid]::new($oid)) }
        $Request.CertificateExtensions.Add([X509EnhancedKeyUsageExtension]::new($oids, $EkuCritical))
    }
    if ($AddSki) { $Request.CertificateExtensions.Add([X509SubjectKeyIdentifierExtension]::new($Request.PublicKey, $false)) }
    if ($OcspNoCheck) { $Request.CertificateExtensions.Add([X509Extension]::new([Oid]::new((getSettings).Oids.Extensions.OcspNoCheck), [byte[]](0x05,0x00), $false)) }
    foreach ($extension in @($AdditionalExtension)) {
        if (-not $extension) { continue }
        if ($Request.CertificateExtensions | Where-Object { $_.Oid.Value -eq $extension.Oid.Value }) { throw "Duplicate extension OID $($extension.Oid.Value)." }
        $Request.CertificateExtensions.Add($extension)
    }
}

function moveNextOutputToTop {
    # Move the viewport, not the buffer contents: the menu remains available in
    # scrollback and Clear-Host is intentionally not used.
    try {
        $rawUi = $Host.UI.RawUI
        $cursor = $rawUi.CursorPosition
        $window = $rawUi.WindowPosition
        $maximumTop = [Math]::Max(0, $rawUi.BufferSize.Height - $rawUi.WindowSize.Height)
        $targetTop = [Math]::Min($cursor.Y, $maximumTop)
        if ($targetTop -gt $window.Y) {
            $rawUi.WindowPosition = [System.Management.Automation.Host.Coordinates]::new($window.X, $targetTop)
        }
        if ($rawUi.WindowPosition.Y -eq $cursor.Y) { return }
    } catch {
        # RawUI is optional (for example in some redirected or remote hosts).
    }

    # VT fallback: scroll the visible viewport into scrollback, then position the
    # cursor at its first row. This still preserves history and does not clear it.
    if (-not [Console]::IsOutputRedirected) {
        try {
            $height = [Math]::Max(1, $Host.UI.RawUI.WindowSize.Height)
            Write-Host -NoNewline "$([char]27)[$($height)S$([char]27)[H"
        } catch {
            # Hosts without RawUI or VT support simply retain the menu.
        }
    }
}

function readList {
    param([Parameter(Mandatory)] [string] $Prompt)
    $answer = Read-Host "$Prompt (comma-separated)"
    if (-not $answer) { return @() }
    @($answer -split ',' | ForEach-Object Trim | Where-Object { $_ })
}

#endregion


#region User-callable functions

<#
.SYNOPSIS
Converts an X.509 certificate between binary DER and Base64 encodings.

.PARAMETER InputObject
DER certificate bytes or a Base64-encoded certificate string.

.PARAMETER OutputFormat
Encoding to return. Defaults to the opposite of the detected input encoding. DER returns byte[]; Base64 returns a string.

.EXAMPLE
$base64 = Convert-X509CertificateEncoding -InputObject $derBytes

.EXAMPLE
$derBytes = Convert-X509CertificateEncoding -InputObject $base64
#>
function Convert-X509CertificateEncoding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $InputObject,
        [ValidateSet('DER', 'Base64')] [string] $OutputFormat
    )

    if ($InputObject -is [byte[]]) {
        $inputFormat = 'DER'
        $derBytes = $InputObject
    } elseif ($InputObject -is [string]) {
        $inputFormat = 'Base64'
        try {
            $derBytes = [Convert]::FromBase64String($InputObject)
        } catch {
            throw "Input is not valid Base64 data. $($_.Exception.Message)"
        }
    } else {
        throw 'InputObject must be a DER byte array or a Base64 string.'
    }

    if (-not $OutputFormat) { $OutputFormat = if ($inputFormat -eq 'DER') { 'Base64' } else { 'DER' } }

    $certificate = $null
    try {
        $certificate = [X509Certificate2]::new($derBytes)
        if ($OutputFormat -eq 'DER') { return ,$certificate.RawData }
        [Convert]::ToBase64String($certificate.RawData)
    } finally {
        if ($certificate) { $certificate.Dispose() }
    }
}

<#
.SYNOPSIS
Builds a data-driven X.509 v3 CertificateRequest for a named usage scenario.

.PARAMETER Scenario
Scenario key from New-X509v3Certificate.Data.psd1. It supplies secure defaults and constraints.

.PARAMETER CommonName
Subject common name (CN); omitted only by profiles whose identity is entirely in a critical SAN.

.PARAMETER Subject
Optional additional Subject attributes keyed by long name or short name (for example O, OU, L, S and C).

.PARAMETER AdditionalExtension
Typed X509Extension objects for issuer/product extensions not safely derived by this script, such as an AD SID or template extension.

.OUTPUTS
System.Security.Cryptography.X509Certificates.CertificateRequest

.EXAMPLE
$request = New-X509CertificateRequest -Scenario TLS-PRV -CommonName 'api.example.test' -DnsName 'api.example.test'
#>
function New-X509CertificateRequest {
    [CmdletBinding()]
    [OutputType([CertificateRequest])]
    param(
        [Parameter(Mandatory)] [string] $Scenario,
        [string] $CommonName,
        [string] $Email,
        [hashtable] $Subject,
        [string[]] $DnsName,
        [string[]] $IpAddress,
        [string[]] $Uri,
        [string[]] $EmailSan,
        [string[]] $Upn,
        [string] $Algorithm,
        [int] $KeySize,
        [string] $Curve,
        [string] $HashAlgorithm,
        [string[]] $KeyUsage,
        [string[]] $EkuOid,
        [Nullable[bool]] $IsCA,
        [Nullable[int]] $PathLength,
        [string[]] $CaIssuerUri,
        [string[]] $OcspUri,
        [string[]] $CrlDistributionPointUri,
        [string[]] $CertificatePolicyOid,
        [switch] $TlsMustStaple,
        [X509Extension[]] $AdditionalExtension
    )

    $settings = getSettings
    $profile = getScenario $Scenario
    if (-not $Algorithm) { $Algorithm = if ($profile.Algorithm) { $profile.Algorithm } else { $settings.Defaults.Algorithm } }
    if (-not $KeySize) { $KeySize = if ($profile.KeySize) { $profile.KeySize } else { $settings.Defaults.RsaKeySize } }
    if (-not $Curve) { $Curve = if ($profile.Curve) { $profile.Curve } else { $settings.Defaults.Curve } }
    if (-not $HashAlgorithm) { $HashAlgorithm = if ($profile.Hash) { $profile.Hash } else { $settings.Defaults.HashAlgorithm } }
    if (-not $PSBoundParameters.ContainsKey('KeyUsage')) { $KeyUsage = @($profile.KeyUsage) }
    if (-not $PSBoundParameters.ContainsKey('EkuOid')) { $EkuOid = @(resolveEkuOids $profile.Eku) }
    else { $EkuOid = @(resolveEkuOids $EkuOid) }
    $isCaValue = if ($PSBoundParameters.ContainsKey('IsCA')) { [bool]$IsCA } else { [bool]$profile.IsCA }
    $pathLengthValue = if ($PSBoundParameters.ContainsKey('PathLength')) { [Nullable[int]]$PathLength } elseif ($null -ne $profile.PathLength) { [Nullable[int]]([int]$profile.PathLength) } else { [Nullable[int]]$null }

    $isEmptySubject = $profile.SubjectMode -eq 'Empty'
    $sanValues = @($DnsName) + @($IpAddress) + @($Uri) + @($EmailSan) + @($Upn) | Where-Object { $_ }
    if ($isEmptySubject -and -not $sanValues) { throw "Scenario '$Scenario' requires a SAN because its Subject is empty." }
    foreach ($requiredType in @($profile.SanTypes)) {
        $present = switch ($requiredType) {
            DNS { @($DnsName).Count -gt 0 }
            IP { @($IpAddress).Count -gt 0 }
            URI { @($Uri).Count -gt 0 }
            Email { @($EmailSan).Count -gt 0 }
            UPN { @($Upn).Count -gt 0 }
        }
        if (-not $present) { throw "Scenario '$Scenario' requires at least one $requiredType SAN value." }
    }
    if ($Scenario -eq 'WORKLOAD' -and (@($Uri).Count -ne 1 -or $Uri[0] -notmatch '^spiffe://')) {
        throw 'WORKLOAD requires exactly one spiffe:// URI SAN.'
    }
    if ($Scenario -eq 'TSA' -and @($EkuOid).Count -ne 1) { throw 'TSA permits only the Time Stamping EKU.' }
    if ($isCaValue -and $EkuOid.Count -gt 0) { Write-Warning 'A CA profile normally omits EKU; this is a deliberately constrained CA request.' }

    $key = newCertificateKey -Algorithm $Algorithm -KeySize $KeySize -Curve $Curve
    try {
        $distinguishedName = convertToDistinguishedName -CommonName $CommonName -Email $Email -Subject $Subject -AllowEmpty:$isEmptySubject
        if ($Algorithm -eq 'RSA') {
            $request = [CertificateRequest]::new($distinguishedName, [RSA]$key, [HashAlgorithmName]::new($HashAlgorithm), [RSASignaturePadding]::Pkcs1)
        } else {
            $request = [CertificateRequest]::new($distinguishedName, [ECDsa]$key, [HashAlgorithmName]::new($HashAlgorithm))
        }
        addSubjectAlternativeName -Request $request -DnsName $DnsName -IpAddress $IpAddress -Uri $Uri -EmailSan $EmailSan -Upn $Upn -Critical:([bool]$profile.SanCritical -or $isEmptySubject)
        $infrastructureExtensions = @(newInfrastructureExtensions -CaIssuerUri $CaIssuerUri -OcspUri $OcspUri -CrlDistributionPointUri $CrlDistributionPointUri -CertificatePolicyOid $CertificatePolicyOid -TlsMustStaple:$TlsMustStaple)
        [X509Extension[]]$allAdditionalExtensions = @($AdditionalExtension | Where-Object { $_ }) + @($infrastructureExtensions | Where-Object { $_ })
        addRequestExtensions -Request $request -KeyUsage $KeyUsage -EkuOid $EkuOid -IsCA $isCaValue -PathLength $pathLengthValue -KeyUsageCritical $true -EkuCritical ([bool]$profile.EkuCritical) -AddSki ([bool]$profile.AddSki) -OcspNoCheck ([bool]$profile.OcspNoCheck) -AdditionalExtension $allAdditionalExtensions

        # Note properties carry creation controls that CertificateRequest itself does not model.
        $request | Add-Member -NotePropertyName X509Scenario -NotePropertyValue $Scenario
        $request | Add-Member -NotePropertyName X509ValidityDays -NotePropertyValue ([int]$profile.ValidityDays)
        $request | Add-Member -NotePropertyName X509RequiresIssuer -NotePropertyValue ([bool]$profile.RequiresIssuer)
        $request | Add-Member -NotePropertyName X509AddSelfAki -NotePropertyValue ([bool]$profile.AddSelfAki)
        $request | Add-Member -NotePropertyName X509PrivateKey -NotePropertyValue $key
        $request
    } catch {
        $key.Dispose()
        throw
    }
}

<#
.SYNOPSIS
Self-signs or issuer-signs a CertificateRequest and stores it, or writes its public certificate to a file.

.PARAMETER Request
A request from New-X509CertificateRequest.

.PARAMETER Context
User for the CurrentUser store, Computer for the LocalMachine store (requires elevation).

.PARAMETER IssuerCertificate
Optional issuer certificate with private key. Required by scenarios such as SUBCA and OCSP.

.PARAMETER Exportable
Makes the persisted private key exportable. The secure default is non-exportable.

.PARAMETER OutputPath
Optional output file path. When supplied, the certificate is not added to a certificate store.

.PARAMETER OutputFormat
File encoding when OutputPath is specified: DER or Base64. The private key is not written to this file.

.OUTPUTS
System.Security.Cryptography.X509Certificates.X509Certificate2

.EXAMPLE
New-X509Certificate -Request $request -Context User
#>
function New-X509Certificate {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([X509Certificate2])]
    param(
        [Parameter(Mandatory)] [CertificateRequest] $Request,
        [ValidateSet('User', 'Computer')] [string] $Context = 'User',
        [X509Certificate2] $IssuerCertificate,
        [int] $ValidityDays,
        [byte[]] $SerialNumber,
        [switch] $Exportable,
        [string] $OutputPath,
        [ValidateSet('DER', 'Base64')] [string] $OutputFormat = 'DER'
    )

    $store = getStoreContext -Context $Context -Exportable:$Exportable
    $requiresIssuer = [bool]$Request.X509RequiresIssuer
    if ($requiresIssuer -and -not $IssuerCertificate) { throw "Scenario '$($Request.X509Scenario)' requires -IssuerCertificate." }
    if ($IssuerCertificate) {
        if (-not $IssuerCertificate.HasPrivateKey) { throw 'IssuerCertificate must contain its private key.' }
        $basicConstraints = $IssuerCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' } | Select-Object -First 1
        if (-not $basicConstraints -or -not ([X509BasicConstraintsExtension]::new($basicConstraints, $basicConstraints.Critical)).CertificateAuthority) {
            throw 'IssuerCertificate is not a CA certificate.'
        }
        $issuerKeyUsage = $IssuerCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.15' } | Select-Object -First 1
        if ($issuerKeyUsage -and -not (([X509KeyUsageExtension]::new($issuerKeyUsage, $issuerKeyUsage.Critical)).KeyUsages -band [X509KeyUsageFlags]::KeyCertSign)) {
            throw 'IssuerCertificate Key Usage does not permit certificate signing.'
        }
    }
    if (-not $ValidityDays) { $ValidityDays = if ($Request.X509ValidityDays) { [int]$Request.X509ValidityDays } else { (getSettings).Defaults.ValidityDays } }
    if ($ValidityDays -lt 1) { throw 'ValidityDays must be at least 1.' }
    $notBefore = [DateTimeOffset]::UtcNow.AddMinutes(-5)
    if ($IssuerCertificate -and $notBefore -lt [DateTimeOffset]$IssuerCertificate.NotBefore.ToUniversalTime()) {
        $notBefore = [DateTimeOffset]$IssuerCertificate.NotBefore.ToUniversalTime()
    }
    $notAfter  = $notBefore.AddDays($ValidityDays)
    if ($IssuerCertificate -and $notAfter -gt [DateTimeOffset]$IssuerCertificate.NotAfter) {
        throw 'The requested NotAfter exceeds the issuer certificate validity.'
    }

    $akiOid = (getSettings).Oids.Extensions.AuthorityKeyIdentifier
    if (-not ($Request.CertificateExtensions | Where-Object { $_.Oid.Value -eq $akiOid })) {
        if ($IssuerCertificate) {
            $Request.CertificateExtensions.Add((newAuthorityKeyIdentifierExtension -KeyIdentifier (getCertificateKeyIdentifier $IssuerCertificate)))
        } elseif ([bool]$Request.X509AddSelfAki) {
            $Request.CertificateExtensions.Add((newAuthorityKeyIdentifierExtension -KeyIdentifier (getSubjectKeyIdentifierBytes $Request)))
        }
    }

    if ($IssuerCertificate -and -not $SerialNumber) {
        $SerialNumber = [byte[]]::new(16)
        $random = [RandomNumberGenerator]::Create()
        try { $random.GetBytes($SerialNumber) } finally { $random.Dispose() }
        $SerialNumber[0] = $SerialNumber[0] -band 0x7f
        if (($SerialNumber | Measure-Object -Sum).Sum -eq 0) { $SerialNumber[15] = 1 }
    }

    $createCertificate = {
        if (-not $IssuerCertificate) { return $Request.CreateSelfSigned($notBefore, $notAfter) }
        $publicOnly = $Request.Create($IssuerCertificate, $notBefore, $notAfter, $SerialNumber)
        try {
            if ($Request.X509PrivateKey -is [RSA]) { return [RSACertificateExtensions]::CopyWithPrivateKey($publicOnly, [RSA]$Request.X509PrivateKey) }
            return [ECDsaCertificateExtensions]::CopyWithPrivateKey($publicOnly, [ECDsa]$Request.X509PrivateKey)
        } finally { $publicOnly.Dispose() }
    }

    if ($OutputPath) {
        $kind = if ($IssuerCertificate) { 'issuer-signed' } else { 'self-signed' }
        if (-not $PSCmdlet.ShouldProcess($OutputPath, "Create $kind certificate for $($Request.SubjectName.Name)")) { return }
        $signed = & $createCertificate
        try {
            saveCertificateToFile -Certificate $signed -Path $OutputPath -Format $OutputFormat
            return $signed
        } catch {
            $signed.Dispose()
            throw
        }
    }

    $action = "Create certificate in $($store.Location)\My"
    if (-not $PSCmdlet.ShouldProcess($Request.SubjectName.Name, $action)) { return }

    # The signed certificate holds an ephemeral key; a PFX round trip persists it in the chosen key store.
    $signed    = & $createCertificate
    $password  = [guid]::NewGuid().ToString()
    $pfx       = $null
    $persisted = $null
    try {
        $pfx       = $signed.Export([X509ContentType]::Pfx, $password)
        $persisted = [X509Certificate2]::new($pfx, $password, $store.KeyFlags)
        addCertificateToStore -Certificate $persisted -StoreName 'My' -Location $store.Location
        $thumbprint = $persisted.Thumbprint
    } finally {
        $signed.Dispose()
        if ($persisted) { $persisted.Dispose() }
        if ($pfx) { [Array]::Clear($pfx, 0, $pfx.Length) }
    }

    $installed = getStoreCertificate -Thumbprint $thumbprint -Location $store.Location
    if (-not $installed) { throw "Certificate $thumbprint was not found in the store after install." }
    $installed
}

<#
.SYNOPSIS
Exports a certificate selected from a certificate store to a file.

.PARAMETER Thumbprint
Thumbprint of the certificate in the selected store. If omitted, the current Cert:\ location must identify a certificate.

.PARAMETER Context
User for CurrentUser, Computer for LocalMachine. Defaults from the current Cert:\ location, or User.

.PARAMETER StoreName
Store containing the certificate. Defaults from the current Cert:\ location, or My.

.PARAMETER Path
Output file path or an existing directory. For a directory, the file name is based on the certificate Subject.

.PARAMETER Format
Output encoding: DER or Base64.

.OUTPUTS
System.String. The path of the .cer file.

.EXAMPLE
Export-X509Certificate -Thumbprint $thumbprint -Context User -StoreName My -Path C:\Certs
#>
function Export-X509Certificate {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [string] $Thumbprint,
        [ValidateSet('User', 'Computer')] [string] $Context,
        [string] $StoreName,
        [Parameter(Mandatory)] [string] $Path,
        [ValidateSet('DER', 'Base64')] [string] $Format = 'DER'
    )

    $current = getCurrentCertificateStore
    if (-not $Context) { $Context = if ($current) { $current.Context } else { 'User' } }
    if (-not $StoreName) {
        $StoreName = if ($current -and $current.Context -eq $Context -and $current.StoreName) { $current.StoreName } else { 'My' }
    }
    if (-not $Thumbprint -and $current -and $current.Context -eq $Context -and $current.StoreName -eq $StoreName) {
        $Thumbprint = $current.Thumbprint
    }
    if (-not $Thumbprint) { throw 'Specify -Thumbprint or run from a Cert:\ location that identifies a certificate.' }

    $location = (getStoreContext -Context $Context).Location
    $certificate = getStoreCertificate -Thumbprint $Thumbprint -Location $location -StoreName $StoreName
    if (-not $certificate) { throw "Certificate $Thumbprint was not found in $location\$StoreName." }

    $isDirectory = (Test-Path -LiteralPath $Path -PathType Container) -or
                   $Path.EndsWith([System.IO.Path]::DirectorySeparatorChar) -or
                   $Path.EndsWith([System.IO.Path]::AltDirectorySeparatorChar)
    if ($isDirectory) {
        if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "Output directory not found: $Path" }
        $name = $certificate.GetNameInfo([X509NameType]::SimpleName, $false)
        $invalidCharacters = [regex]::Escape((-join [System.IO.Path]::GetInvalidFileNameChars()))
        $safeName = ($name -replace "[$invalidCharacters]", '_').TrimEnd([char[]]@(' ', '.'))
        if ([string]::IsNullOrWhiteSpace($safeName)) { throw 'The certificate subject does not produce a valid file name.' }
        $extension = if ($Format -eq 'DER') { '.cer' } else { '.b64' }
        $outputPath = Join-Path -Path $Path -ChildPath "$safeName$extension"
    } else {
        $outputPath = $Path
        $parent = Split-Path -Path $outputPath -Parent
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw "Output directory not found: $parent" }
    }

    try {
        if ($PSCmdlet.ShouldProcess($outputPath, "Export $Format certificate $($certificate.Thumbprint)")) {
            saveCertificateToFile -Certificate $certificate -Path $outputPath -Format $Format
            if (-not (Test-Path -LiteralPath $outputPath -PathType Leaf)) { throw "File export failed: $outputPath" }
            $outputPath
        }
    } finally {
        $certificate.Dispose()
    }
}

<#
.SYNOPSIS
Imports a .cer file into one or more existing certificate stores.

.DESCRIPTION
When the current location is on the Cert:\ drive (for example Cert:\CurrentUser\Root), an omitted
Context and StoreName default to that location.

.PARAMETER Path
Path of the .cer file.

.PARAMETER Context
User for the CurrentUser stores, Computer for the LocalMachine stores (requires elevation).

.PARAMETER StoreName
One or more existing store names, such as My, Root, CA or TrustedPublisher.

.EXAMPLE
Install-X509Certificate -Path C:\Certs\DemoSigner.cer -Context User -StoreName Root, TrustedPublisher -WhatIf

.EXAMPLE
cd Cert:\CurrentUser\TrustedPublisher; Install-X509Certificate -Path C:\Certs\DemoSigner.cer
#>
function Install-X509Certificate {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [ValidateSet('User', 'Computer')] [string] $Context,
        [string[]] $StoreName
    )

    if (-not (Test-Path -Path $Path -PathType Leaf)) { throw "Certificate file not found: $Path" }

    $current = getCurrentCertificateStore
    if (-not $Context -and $current) { $Context = $current.Context }
    if (-not $StoreName -and $current -and $current.StoreName -and $current.Context -eq $Context) {
        $StoreName = $current.StoreName
    }
    if (-not $Context -or -not $StoreName) {
        throw 'Specify -Context and -StoreName, or run from a Cert:\<CurrentUser|LocalMachine>\<Store> location.'
    }

    $location    = (getStoreContext -Context $Context).Location
    $certificate = [X509Certificate2]::new($Path)

    try {
        foreach ($name in $StoreName) {
            if ($PSCmdlet.ShouldProcess("$location\$name", "Install certificate $($certificate.Thumbprint)")) {
                try {
                    addCertificateToStore -Certificate $certificate -StoreName $name -Location $location
                    if (-not (getStoreCertificate -Thumbprint $certificate.Thumbprint -Location $location -StoreName $name)) {
                        throw "Certificate was not found in $location\$name after import."
                    }
                } catch {
                    throw "Failed to install into $location\$name. Earlier stores in this request may already have been updated. $($_.Exception.Message)"
                }
            }
        }
    } finally {
        $certificate.Dispose()
    }
}

#endregion


#region Interactive wizard

<#
.SYNOPSIS
Prompts for the certificate options, then creates, exports and (for code signing) trusts the certificate.
#>
function Invoke-X509CertificateWizard {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    # Optional profile keys are intentionally absent from some data records.
    # Disable inherited StrictMode only in this function scope/call tree; the
    # caller's StrictMode setting is unchanged when the wizard returns.
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Off

    Write-Host "X.509 v3 certificate wizard (research cutoff $((getSettings).ResearchCutoff))`n"
    $settings = getSettings
    foreach ($item in $settings.Scenarios | Sort-Object Frequency) {
        Write-Host (' [{0,2}] {1,-12} {2}' -f $item.MenuKey, $item.Key, $item.Name)
    }
    $selection = readChoice -Prompt 'Choose a scenario number' -ValidChoices @($settings.Scenarios.MenuKey)
    moveNextOutputToTop
    $profile = $settings.Scenarios | Where-Object MenuKey -eq $selection | Select-Object -First 1
    Write-Host "`nSelected: $($profile.Key) - $($profile.Name)"
    if ($profile.Warning) { Write-Warning $profile.Warning }

    $defaultLetter = if ($profile.Context -eq 'Computer') { 'C' } else { 'U' }
    $answer = readChoice -Prompt "Store certificate for User or Computer? [U/C], profile default $defaultLetter" -ValidChoices 'U', 'C', ''
    if (-not $answer) { $answer = $defaultLetter }
    $context = if ($answer -eq 'U') { 'User' } else { 'Computer' }
    $location = (getStoreContext -Context $context).Location

    $commonName = $null
    if ($profile.SubjectMode -ne 'Empty') {
        $commonName = Read-Host 'Subject common name (CN)'
        if (-not $commonName) { throw 'A subject common name is required.' }
        if (testExistingCertificate -CommonName $commonName -Location $location) { Write-Warning 'Other certificates for that subject exist.' }
    }

    $requestArguments = @{ Scenario=$profile.Key; CommonName=$commonName }
    foreach ($sanType in @($profile.SanTypes)) {
        switch ($sanType) {
            DNS   { $requestArguments.DnsName  = readList 'DNS SAN values' }
            IP    { $requestArguments.IpAddress = readList 'IP SAN values' }
            URI   { $requestArguments.Uri      = readList 'URI SAN values' }
            Email { $requestArguments.EmailSan = readList 'Email SAN values' }
            UPN   { $requestArguments.Upn      = readList 'UPN SAN values' }
        }
    }
    $request = New-X509CertificateRequest @requestArguments

    $issuer = $null
    if ($profile.RequiresIssuer) {
        $issuerThumbprint = (Read-Host "Issuer thumbprint in $location\My").Replace(' ', '')
        if (-not $issuerThumbprint) { throw "Scenario '$($profile.Key)' requires an issuer certificate." }
        $issuer = getStoreCertificate -Thumbprint $issuerThumbprint -Location $location
        if (-not $issuer) { throw "Issuer $issuerThumbprint was not found in $location\My." }
    }
    $exportAnswer = readChoice -Prompt 'Allow the installed private key to be exported? [Y/N], default N' -ValidChoices 'Y','N',''
    $certificateArguments = @{ Request=$request; Context=$context; IssuerCertificate=$issuer; Exportable=($exportAnswer -eq 'Y'); WhatIf=$WhatIfPreference }
    $certificate = New-X509Certificate @certificateArguments
    if (-not $certificate) { return }
    Write-Host "Certificate creation: Completed successfully. Thumbprint $($certificate.Thumbprint)" -ForegroundColor Green

    $outputPath = Read-Host 'Optional file path or existing directory for the public .CER (Return to skip)'
    if ($outputPath) {
        try {
            $cerPath = Export-X509Certificate -Thumbprint $certificate.Thumbprint -Context $context -StoreName 'My' -Path $outputPath -WhatIf:$WhatIfPreference
            if ($cerPath) { Write-Host "Certificate export: $cerPath" -ForegroundColor Green }
        } catch { Write-Warning "Certificate export failed: $($_.Exception.Message) The certificate remains in the personal store." }
    }
    Write-Host "Certificate path: Cert:\$location\My\$($certificate.Thumbprint)"
    if ($profile.Key -eq 'CODE') { Write-Host 'Trust distribution is intentionally separate; the wizard never inserts a self-signed leaf into Root.' }
}

#endregion


# Run the wizard unless the script is dot-sourced.
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-X509CertificateWizard
}
