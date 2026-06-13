#           _          _
#        __| |____ ___| |__
#       / _  |__  / __| '_ \           Script: '3.02 Custom PSProvider.ps1'
#      | (_| |(_| \__ \ | | |          Author: Paul 'Dash'
#       \__,_\__,_|___/_| |_(_)        E-mail: paul@dash.training
#       T  R  A  I  N  I  N  G

# Simple read-only custom PSProvider that exposes local port ownership.
# Associated with Custom Format demo.


# Reference:
# https://github.com/MicrosoftDocs/PowerShell-Docs/blob/main/reference/docs-conceptual/developer/provider/windows-powershell-provider-overview.md
#

# CLEANUP

# Remove any earlier demo state from this session so the provider can be recreated cleanly.
# PowerShell cannot truly unload assemblies loaded into the current process, so the demo also uses
# a unique DLL name per script run to avoid collisions with prior compilations.
if (Get-PSDrive -Name Port -ErrorAction SilentlyContinue) {
    Remove-PSDrive -Name Port -Force
}

# The imported binary module is what registers the custom provider name with PowerShell.
Get-Module |
    Where-Object Path -like (Join-Path -Path $env:TEMP -ChildPath 'NetworkPortProvider.*.dll') |
    Remove-Module -Force -ErrorAction SilentlyContinue

# Clean up leftover temporary DLLs from older runs where possible.
Get-ChildItem -LiteralPath $env:TEMP -Filter 'NetworkPortProvider.*.dll' -ErrorAction SilentlyContinue |
    ForEach-Object {
        if (Test-Path -LiteralPath $_.FullName) {
            Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
        }
    }

# SETUP

# Load the C# source that defines the provider class and the objects the provider returns.
$providerSourcePath = Join-Path -Path $PSScriptRoot -ChildPath '3.02 Custom PSProvider.cs'
$formatDataPath = Join-Path -Path $PSScriptRoot -ChildPath '3.02 Custom Format.format.ps1xml'
$providerSource = Get-Content -LiteralPath $providerSourcePath -Raw

# Hash the source so that a changed provider definition gets a new assembly filename.
$providerHash = [System.BitConverter]::ToString(
    [System.Security.Cryptography.SHA256]::Create().ComputeHash(
        [System.Text.Encoding]::UTF8.GetBytes($providerSource)
    )
).Replace('-', '').Substring(0, 12)

# COMPILE AND REGISTER

# Compile the provider into a temporary binary module that PowerShell can import.
$providerAssemblyPath = Join-Path -Path $env:TEMP -ChildPath ("NetworkPortProvider.{0}.{1}.dll" -f $providerHash, $PID)
$providerLoaded = Get-Module | Where-Object Path -eq $providerAssemblyPath | Select-Object -First 1

if (-not $providerLoaded) {
    if (Test-Path -LiteralPath $providerAssemblyPath) {
        Remove-Item -LiteralPath $providerAssemblyPath -Force
    }

    try {
        # Create the assembly from the C# source.
        # The provider class is decorated with attributes that tell PowerShell how to use it.
        Add-Type -TypeDefinition $providerSource `
                 -Language CSharp `
                 -OutputAssembly $providerAssemblyPath `
                 -ErrorAction Stop
    }
    catch {
        if (Test-Path -LiteralPath $providerAssemblyPath) {
            Remove-Item -LiteralPath $providerAssemblyPath -Force -ErrorAction SilentlyContinue
        }
        throw "Failed to compile the NetworkPort provider: $($_.Exception.Message)"
    }

    # Import the compiled assembly as a module to make the provider available to PowerShell.
    Import-Module -Name $providerAssemblyPath -Force
}

# CREATE THE PSDRIVE

# Creating the PSDrive is the moment the provider becomes visible to users as Port:\
# The provider name comes from the [CmdletProvider()] attribute in the C# class.
New-PSDrive -Name Port -PSProvider NetworkPort -Root '\' | Out-Null

# LOAD FORMAT DATA

# Import the formatting rules separately so object display concerns stay out of the provider code.
Update-FormatData -PrependPath $formatDataPath

# Example commands for the demo:
# Get-ChildItem Port:\
# Get-ChildItem Port:\TCP
# Get-Item Port:\TCP\443
# Get-ChildItem Port:\TCP\443
# Get-Item Port:\TCP\443\1
# Get-Item Port:\UDP\53
