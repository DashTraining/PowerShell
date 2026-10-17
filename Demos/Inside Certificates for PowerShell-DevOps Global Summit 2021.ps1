#
#        _| _ __|_           Script:  'Inside Certificates.ps1' 
#       (_|(_|_)| ) .        Author:  Paul 'Dash' Wojcicki-Jarocki
#      t r a i n i n g       Contact: paul@dash.training
#                            Created: 2021-03-31
#
###############################################################################

# created for the PowerShell + DevOps Global Summit 2021
# session entitled Inside Certificates
# TODO: Split this conference runbook into focused, independently runnable labs with explicit Windows/admin prerequisites and deterministic fixtures.
# TODO: Replace personal drives/domains and guard certificate-store, WSMan, firewall, IIS, Azure, and module-install changes with ShouldProcess plus cleanup/rollback instructions.

break # Don't run top-to-bottom!



# DATA-IN-USE
###############################################################################
# besides the well-recognized Data-at-Rest and Data-in-Motion

'My secret is good coffee' | ConvertTo-SecureString -AsPlainText
                             # the cmdlet doesn't like the fact that the string
                             # is already in memory in an unencrypted format



# CLASSIC CIPHERS
###############################################################################
# Ceaser Cipher, a simple substitution by shifting the alphabet

function CeaserCipherAlgorithm {
    param($Plaintext, $Key)

    [char[]]$Alphabet   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    [string]$Ciphertext = ''

    foreach ($char in $Plaintext) {
        if ($char -in $Alphabet) {
            $Newindex = (($Alphabet.IndexOf($char) + $Key) % $Alphabet.Count)
            $Ciphertext += $Alphabet[$Newindex]
        } else {
            $Ciphertext += $char
        }
    } # foreach

    Write-Output $Ciphertext
} # function

cls
   [int]$Key1      = 3
[char[]]$Plaintext = 'COFFEE CAME TO EUROPE IN THE SIXTEENTH CENTURY'

$Ciphertext = CeaserCipherAlgorithm $Plaintext $Key1
$Ciphertext



# MODERN CIPHERS
###############################################################################
# symmetrical encryption shown here with the .NET AES abstract class

cls
[char[]]$Key2 = 'Where have you BEAN all my life?'
$Plaintext    = "It's hard to ESPRESSO my feelings for you. I like you a LATTE."

# Choose the algorithm and set the key
$AESAlgorithm     = [System.Security.Cryptography.Aes]::Create()
$AESAlgorithm
$AESAlgorithm.Key = $Key2

# Convert input
$PlainBytesIn = [System.Text.Encoding]::UTF8.GetBytes($Plaintext)

# Encrypt
$Encryptor    = $AESAlgorithm.CreateEncryptor()
$CipherBytes  = $Encryptor.TransformFinalBlock($PlainBytesIn, 0, $PlainBytesIn.Length);
$CipherText   = [System.Convert]::ToBase64String($CipherBytes)

$Ciphertext

# Decrypt
$Decryptor     = $AESAlgorithm.CreateDecryptor();
$PlainBytesOut = $Decryptor.TransformFinalBlock($CipherBytes, 0, $CipherBytes.Length)

[System.Text.Encoding]::UTF8.GetString($PlainBytesOut)



# CALCULATING ONE-WAY FUNCTION
###############################################################################
# using the 256-bit version of SHA-2

cls
[string]$Plaintext = (Get-Content S:\CoffeeRecipe.txt -Raw)

[byte[]]$PlainBytesIn = $Plaintext.ToCharArray()

$SHAAlgorithm = [System.Security.Cryptography.SHA256]::Create()
$HashBytes    = $SHAAlgorithm.ComputeHash($PlainBytesIn)

$HashBytes.Length * 8   # always 256 bits output for SHA256

$Hash         = ([System.BitConverter]::ToString($HashBytes)).Replace('-','')
$Hash

# Above will work for any data, but for files
# a hash can also be calculated quickly using:
(Get-FileHash -Path S:\CoffeeRecipe.txt).Hash

# useful for confirming files were properly downloaded
# against hashes published on developer's website



# INSIDE A CERTIFICATE
###############################################################################
# navigating the PSDrive for Certificates

Get-ChildItem Cert:\
Get-ChildItem Cert:\CurrentUser\
Get-ChildItem Cert:\CurrentUser\My\

cls
# Here's my own self-issued e-mail signing certificate
# (change the filter to load a certificate you own)
$Cert1 = Get-ChildItem Cert:\CurrentUser\My\* |
         Where-Object Subject -like "CN=Paul Dash*"

$Cert1 | 
Select-Object Subject,
              @{N='PublicKey';
                E={([BitConverter]::ToString(
                    $_.PublicKey.EncodedKeyValue.RawData)).Replace('-','')}},
              NotBefore, NotAfter,
              @{N='Extensions';
                E={$_.Extensions.Oid}},
              Version, SerialNumber, Issuer



# EXTENSIONS: POLICIES
###############################################################################
# Microsoft's Certificate Policy and Certification Practice Statement:
# https://www.microsoft.com/pki/mscorp/cps/default.htm



# EXPLORING OIDs
###############################################################################
# standardized ways of describing algorithms, key usage, policies...

$Cert1.Extensions.Oid

# Here we can translate an OID into its  friendly name
[System.Security.Cryptography.Oid]'2.5.29.37'
[System.Security.Cryptography.Oid]'1.3.6.1.5.5.7.3.1'
[System.Security.Cryptography.Oid]'Code Signing'

# Companies can also use these data structures to hold useful information
# Private Enterprise Number can be requested on https://pen.iana.org/pen/PenApplication.page
# Good OID search http://www.oid-info.com/basic-search.htm
$OID = New-Object System.Security.Cryptography.Oid('1.3.6.1.4.1.53698', 'Gray Day Cafe')



# SUBJECT NAMING
###############################################################################
# many forms of names used inside the certificate

$Cert2 = Get-ChildItem Cert:\LocalMachine\ADDRESSBOOK |
         Where-Object Subject -like "*.microsoft.com*"

# an easy way to do this #Requires -Version 7.1
Get-ChildItem -Path Cert:\ -DnsName microsoft.com -Recurse

cls
# X500 Distinguished Name format
$Cert2.SubjectName.Name -split ', ' | Out-String

# If this extension is present, we can list IPs, DNS Names, URIs, e-mail addresses
$Cert2.Extensions['2.5.29.17'].Oid
# But we have to decode it from Abstract Syntax Notation One (ASN.1)
# Format method argument TRUE for multi-line output
([System.Security.Cryptography.AsnEncodedData]::new(
            $Cert2.Extensions['2.5.29.17'].Oid,
            $Cert2.Extensions['2.5.29.17'].RawData)).Format($true)

# blank by default, this can be set by a user after the certificate has been issued
$Cert2.FriendlyName
$Cert2.FriendlyName = 'Microsoft Websites DEMO'


# SELF-SIGNED CERTIFICATES part 1
###############################################################################
# using the COM object is powerfull but tedious

cls
# Prepare the private key
$Key3 = New-Object -ComObject 'X509Enrollment.CX509PrivateKey.1'
$Key3.MachineContext = 1
$Key3.Create()

# Specify the subject
$Subject           = 'GrayDayCafe.test'
$DistinguishedName = New-Object -ComObject "X509Enrollment.CX500DistinguishedName.1"  
$DistinguishedName.Encode("CN=$Subject", 0)

# Create the certificate request (that would get sent to a CA)
$CertReq = New-Object -ComObject 'X509Enrollment.CX509CertificateRequestCertificate.1'
$CertReq.InitializeFromPrivateKey(2, $Key3, "") # context 2 = COMPUTER
$CertReq.Subject = $DistinguishedName
$CertReq.Encode()

# Send request
$Enrollment = New-Object -ComObject 'X509Enrollment.CX509Enrollment.1'
$Enrollment.InitializeFromRequest($CertReq)

# Check if certificate enrollment succeeded
$Enrollment.Status.ErrorText
# Receive requested certificate in DER-encoded format
$Cert3 = $Enrollment.CreateRequest(0)
$Cert3

$Enrollment.CertificateFriendlyName = 'GDC Test 3'

# Install into certificate store
# https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509enrollment-installresponse
# Restrictions = 4 (AllowUntrustedRoot)
# Encoding     = 0 (XCN_CRYPT_STRING_BASE64HEADER)
$Enrollment.InstallResponse(4, $Cert3, 0, "")



# SELF-SIGNED CERTIFICATES part 2
###############################################################################
# using the cmdlet introduced in Server 2012/Windows 8

cls
# Quickest way to create a certificate
# as SSLServerAuthentication is the default Type
# and Subject will get derived from DnsName
New-SelfSignedCertificate -DnsName 'GrayDayCafe.test' `
                          -FriendlyName 'GDC Test 4'
# That was easy!

# You gain more control by defining your own extensions:
# - Subject Alternative Name including server IP
# - Certificate Policy
# - Enhanced Key Usage
$Extensions = @('2.5.29.17={text}IPAddress=10.11.12.13&DNS=GrayDayCafe.test&DNS=10.11.12.13',
                '2.5.29.32={text}OID=1.3.6.1.4.1.53698.1&Notice=You found another Easter Egg!',
                '2.5.29.37={text}1.3.6.1.5.5.7.3.1')

# ...and with lots of parameters
$Cert5Params = @{ Subject         = 'CN=GrayDayCafe.test,O=Gray Day Cafe';
                  FriendlyName    = 'GDC Test 5';
                  TextExtension   = $Extensions; # from above
                  Provider        = 'Microsoft Software Key Storage Provider';
                  HashAlgorithm   = 'SHA256';
                  KeyAlgorithm    = 'RSA';
                  KeyLength       = 2048;
                  KeyExportPolicy = 'Exportable';
                  KeyProtection   = 'None' }
                # NotBefore and NotAfter should also be set to your liking
                # Trend now is to use short expiration dates of 1~3 months

$Cert5 = New-SelfSignedCertificate @Cert5Params
$Cert5



# PSREMOTING OVER WINRM WITH HTTPS
###############################################################################
#region ON_REMOTE

# Explaining the problem
# Across untrusted domains (or in workgroups), Negotiate authentication
# will choose NTLM, which does not guarantee server identity
                                                # DEFAULT VALUES:
Get-ChildItem WSMan:\localhost\Service\Auth     # Kerberos and Negotiate are ON
Get-ChildItem WSMan:\localhost\Listener         # HTTP only

# Add HTTPS Listener
New-Item -Path WSMan:\localhost\Listener `
         -Transport HTTPS `
         -Address 'IP:10.11.12.13' `
         -CertificateThumbPrint $Cert5.Thumbprint `
         -Force

# Allow traffic on TCP 5986
New-NetFirewallRule -DisplayName 'Windows Remote Management (HTTPS-In)' `
                    -Name 'Windows Remote Management (HTTPS-In)' `
                    -Description 'DEMO of WSMan over HTTPS' `
                    -Direction Inbound `
                    -Protocol TCP `
                    -LocalPort 5986 `
                    -Action Allow `
                    -Profile Any # consider using on Private profile only


# Block TCP 5985 traffic and disable HTTP Listener
Disable-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)"
Set-WSManInstance -ResourceURI winrm/config/listener `
                  -SelectorSet @{Address='*';Transport='HTTP'} `
                  -ValueSet @{Enabled='false'}
Restart-Service WinRM

#endregion

#region ON_LOCAL
cls
$RemotingParams = @{ ComputerName = '10.11.12.13';
                     Credential   = (Get-Credential) }

# Test if the connectivity is going to work
Test-WSMan @RemotingParams -UseSSL -Authentication Negotiate

# To prevent error about unknown certificate authority
$PSSessionOption = New-PSSessionOption -SkipCACheck
Enter-PSSession @RemotingParams -UseSSL -SessionOption $PSSessionOption

# NOTE: Starting PowerShell 6, you can do PSRemoting over SSH
# to Linux systems and use certificates for authentication
#endregion



# SSL CERTIFICATES IN IIS
###############################################################################
# using regular certificates (not SNI) in Windows certificate storage

# Server Name Indication (SNI) is an extension to the TLS protocol.
# It allows a client or browser to indicate which hostname it is trying to connect to at the start of the TLS handshake.
# This allows the server to present multiple certificates on the same IP address and port number.


# certificates for IIS need to be in this Certificate Store
Get-ChildItem Cert:\LocalMachine\WebHosting
Copy-Item -Path "Cert:\LocalMachine\My\$($Cert5.Thumbprint)" `
          -Destination 'Cert:\LocalMachine\WebHosting'
# Copy-Item not supported by this PSProvider, although Move-Item is!

# source is our certificate
$IISCert = Get-Childitem cert:\LocalMachine\My |
           Where-Object { $_.Subject -like '*GrayDayCafe.test*' }
# destination Certificate Store
$DestStore = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store `
                        -ArgumentList 'WebHosting','LocalMachine'
$DestStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$DestStore.Add($IISCert)
$DestStore.Close()

# We need to bind the HTTPS protocol to the website and assign the right certificate
New-WebBinding -Name "Default Web Site" -IPAddress "*" -Port 443 -HostHeader "GrayDayCafe.test" -Protocol "https"
(Get-WebBinding -Port 443 -Protocol 'HTTPS').AddSslCertificate($IISCert.Thumbprint, "WebHosting")
Get-WebBinding

# We could also store .PFX certificate files in a Centralized Certificate Store
# on a network share and have IIS automatically select the right one.



# ACME CERTIFICATE REQUEST
# FOR AZURE APPSERVICE
###############################################################################
# Let's Encrypt, a non-profit Certification Authority has a list of 
# ACME (RFC8555) protocol clients https://letsencrypt.org/docs/client-options/
# including PowerShell modules

Install-Module -Name Posh-ACME -Scope AllUsers

                   # SHORT DIGRESSION ABOUT TLS VERSIONS
                   ############################################################
                   # up to version 1.1 have been deprecated,
                   # so check what you're using:
                   [System.Net.ServicePointManager]::SecurityProtocol

# setup of Azure permissions is described in the plugin documentation
# https://github.com/rmbolger/Posh-ACME/blob/main/Posh-ACME/Plugins/Azure-Readme.md

# I already connected to my Azure account
Get-AzContext

$LetsEncryptParams = @{ Domain     = 'test.GrayDayCafe.com';
                        Contact    = 'paul@dash.training';
                        AcceptTOS  = $true;    # Terms of Service
                        Plugin     = 'Azure';
                        PluginArgs = @{ AZSubscriptionId = (Get-AzContext).Subscription.Id;
                                        AZAccessToken    = (Get-AzAccessToken).Token } }
# Verify domain ownership and
# retrieve the certificate
$Cert6 = New-PACertificate @LetsEncryptParams

# Show the interesting properties
$Cert6 | Select-Object @{N='Domain';E={($_.AllSANs)[0]}},Thumbprint,PfxFullChain,PfxPass | Format-List
$Key6Password = ([pscredential]::new('PFX',$Cert6.PfxPass).GetNetworkCredential().Password)

# Nothing left to look at in DNS!
# The record used to validate domain ownership has been cleaned up for us
Get-AzDnsRecordSet -ResourceGroupName Demo -ZoneName test.graydaycafe.com 

# Add binding to Custom Domain Name
New-AzWebAppSSLBinding -WebAppName 'graydaycafe' `
                       -ResourceGroupName 'gdc-rg' `
                       -Name ($Cert6.AllSANs)[0] `
                       -CertificateFilePath $Cert6.PfxFullChain `
                       -CertificatePassword $Key6Password `
                       -SslState SniEnabled



# CERTIFICATE VALIDATION
###############################################################################
# Using the excellent free tool by PKI Solutions:
# GitHub: https://github.com/PKISolutions/SSLVerifier.WPF
# Info:   https://www.pkisolutions.com/ssl-certificate-verifier-tool-v1-5-4-update/

cls
# This may #Requires -RunAsAdministrator
Add-Type -Path 'C:\Program Files\PKI Solutions\SSL Verifier\SSLVerifier.Core.dll'

$WebSiteCert = New-Object SSLVerifier.Core.Default.ServerEntry 'test.GrayDayCafe.com'

$SSLVerifierConfig = New-Object SSLVerifier.Core.Default.CertProcessorConfig
$SSLVerifierConfig
$SSLVerifierConfig.SslProtocolsToUse += [System.Security.Authentication.SslProtocols]::Tls13

$SSLVerifier = New-Object SSLVerifier.Core.Processor.CertProcessor $SSLVerifierConfig
$SSLVerifier.StartScan($WebSiteCert)

# properties scanner will fill in: ItemStatus, SAN, ChainStatus, Certificate and Tree
$WebSiteCert.ItemStatus  # should show Valid
$WebSiteCert.ChainStatus # should show NoError



# SERVER CRYPTOGRAPHY SUITES
###############################################################################
# A best practice is to remove protocols, ciphers, hashes and key exchange algorithms
# that are seen as outdated or compromised. This tool can help.
# No PowerShell, but there's a CLI version:
# https://www.nartac.com/Products/IISCrypto/



# CODE SIGNING
###############################################################################
# signing may be required under your Execution Policy

cls
$Cert7 = Get-ChildItem Cert:\ -Recurse -CodeSigningCert |
         Where-Object NotAfter -gt (Get-Date)

# Important settings of a code-signing certificate
$Cert7 | 
Select-Object Subject,              
              @{N='KeyUsage';
                E={([System.Security.Cryptography.AsnEncodedData]::new(
                    $_.Extensions['2.5.29.15'].Oid,
                    $_.Extensions['2.5.29.15'].RawData)).Format($false)}},
              EnhancedKeyUsageList, HasPrivateKey, Thumbprint

# Same certificate in multiple Certificate Stores for it to be trusted
Get-ChildItem -Path Cert:\ -Recurse |
Where-Object Thumbprint -eq $Cert7.Thumbprint |
Select-Object Subject,PSParentPath

Set-AuthenticodeSignature -Certificate $Cert7 `
                          -FilePath S:\CafeScript.ps1 `
                          -TimestampServer 'http://tsa.starfieldtech.com'
# Pretty recent list of Time Stamp Authorities:
# https://kbpdfstudio.qoppa.com/list-of-timestamp-servers-for-signing-pdf/

###############################################################################
# Th-th-th-that's all folks!
