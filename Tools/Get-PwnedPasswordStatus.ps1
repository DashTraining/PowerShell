#           _          _       
#        __| |____ ___| |__    
#       / _  |__  / __| '_ \           Script: 'ADMembership.ps1'
#      | (_| |(_| \__ \ | | |          Author: Paul 'Dash'
#       \__,_\__,_|___/_| |_(_)        E-mail: paul@dash.training
#       T  R  A  I  N  I  N  G 

<#
.SYNOPSIS
Uses the "Have I Been Pwned" API to check if a password has been exposed in a data breach.
.NOTES
Documented here: https://haveibeenpwned.com/API/v3?ref=troyhunt.com#SearchingPwnedPasswordsByRange
Does NOT expose any data outside of the local system.
#>
[cmdletBinding()]
param(
    # Password to be checked
    [Parameter(Mandatory=$true)]
    [System.Security.SecureString]$Password,

    # Returns only an integer of number of occurences
    [switch]$Quiet
)

$PasswordHash = -join [System.Security.Cryptography.SHA1CryptoServiceProvider]::new().ComputeHash([Text.Encoding]::Utf8.GetBytes(($Password |
Unprotect-SecureString))).ForEach{$_.ToString("X2")}
$Password.Dispose()

$HashList     = (Invoke-WebRequest -Method Get -Uri "https://api.pwnedpasswords.com/range/$($PasswordHash.Substring(0,5))").Content.Split("`n")
$Search       = $PasswordHash.Substring(5)
$Count        = 0
foreach ($line in $HashList) {
    if ($line.Contains($Search)) {
        $Count = $line.Split(':')[1] -as [int]
        break
    } 
}

if ($Quiet.IsPresent) {
    return $Count
}

if ($Count) {
    Write-Output "This password has been seen $Count times before!" -ForegroundColor Red -BackgroundColor White
} else {
    Write-Output "This password wasn't found." -ForegroundColor Green -BackgroundColor White
}
