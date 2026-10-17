#
#        _| _ __|_           Script:  'Zero-to-Hero-CLASSNOTES.ps1' 
#       (_|(_|_)| ) .        Author:  Paul 'Dash'
#      t r a i n i n g       Contact: paul@dash.training
#                            Created: 2019-03-13
#


# CLASS NOTES
# from my "Zero to Hero" 1-day training
# TODO: Turn the monolithic instructor runbook into timed, independently runnable chapters with setup, expected output, exercises, and reset steps.
# TODO: Replace C:/S:/T:/X:, live remoting, and legacy WMI/EventLog assumptions with portable fixtures or clearly labelled optional Windows labs.

break # so whole thing won't run if you press F5 on this file!


########### FINDING CMDLETS

Get-Command -Name *Item*
Get-Command -Noun Item
Get-Command -Verb Stop
Get-Command -Module Hyper-V


########### GETTING HELP

Update-Help

Get-Help dir
# then use -Detailed OR -Full OR better yet:
Get-Help dir -ShowWindow
# SYNTAX section shows:
# Get-ChildItem [[-Path] <String[]>]
dir
dir -Path C:\
dir C:\
dir -Path C:\, S:\, .

Get-Help about_*
Get-Help about_CommonParameters -ShowWindow
del X:\Windows\explorer.exe -WhatIf


########### MODULES

Get-Module
Get-Module -ListAvailable

Find-Module -Name *WSUS* # looks at the PowerShellGallery.com repository
#Install-Module PoshWSUS # running this will install a module on your system


########### Review of Lab Exercise 1

get-help Get-EventLog 

Set-Service -?

Get-NetFirewallRule -?
get-help Get-NetFirewallRule -ShowWindow
Get-NetFirewallRule -Enabled true

Get-WindowsEdition -Online

Get-Module
Get-Volume
Get-Module


########### PIPELINE

dir C:\Windows | more # this needs to be run in the console

Get-Process | Get-Member
Get-Process | Sort-Object -Property WS -Descending | Select-Object -First 3

Get-ChildItem | Get-Member
Get-ChildItem | Select-Object -Property Name,Length,LastAccessTime

# Creating your own property
Get-ChildItem | Select-Object -Property Name, @{Name='LengthInKB';Expression={$_.Length / 1KB}}, Length
Get-ChildItem | Select-Object -Property Name, @{Name='LengthInKB';Expression={$_.Length / 1KB}}, Length | Get-Member


########### FILTERING

<CMDLET> | Where-Object PROPERTY -OPERATOR VALUE  # basic syntax of the Where-Object filter

Get-Help about_Comparison_Operators -ShowWindow

# Comparing numbers
2 -gt 3
4 -lt 777

# Comparing strings
'hello' -eq 'HELLO'     # case-insensitive
'hello' -Ceq 'HELLO'    # case-sensitive
'hello' -like "*LL*"    # true
'hello' -like "*LLL*"   # false

Get-Service -Running # no built-in filtering
Get-Service | Get-Member
Get-Service | Where-Object Status -EQ 'Running'   # displays only the RUNNING services


########### FORMATING

dir | format-wide -AutoSize -Property LastAccessTime

dir | Format-List -Property Name, LastAccessTime
dir | Format-List -Property *

dir | Format-Table  -Property Name, LastAccessTime | gm    # produces format information
dir | select-object -Property Name, LastAccessTime | gm    # retains the original objects

dir | Format-Table -AutoSize -HideTableHeaders -Wrap


########### REDIRECTING OUTPUT
dir                                                    #
dir | Out-Default                                      #
dir | Out-Host                                         # these 3 are the same!

dir | Out-File -FilePath T:\dir.txt                    # output to a text file
dir | Export-Csv -Path T:\dir.csv -Delimiter ';'
Invoke-Item T:\dir.csv
Import-Csv T:\dir.csv | gm
dir | export-clixml -Path T:\dir.xml                   # export maintaining object structure
Invoke-Item T:\dir.xml
Import-Clixml T:\dir.xml | gm

dir | Out-Printer -Name PDF
dir | Out-Null
dir | Out-GridView

Get-Process | select-object Name | Out-GridView -OutputMode Single | Stop-Process -WhatIf

"It's lunch time!" | Out-Voice


########### Review of Lab Exercise 2

get-help Get-EventLog -ShowWindow
get-eventlog -LogName Security | gm

Get-EventLog -LogName Security -InstanceId 4616 | Select-Object -First 10 # works, but is slow

# we can compare speed of commands and see that using the cmdlet with just parameters is faster!
Measure-Command {
    Get-EventLog -LogName Security | Where-Object InstanceID -eq 4616 | Select-Object -First 10 }

Measure-Command {
    Get-EventLog -LogName Security -InstanceId 4616 -Newest 10 }

Set-Location Cert:
Get-ChildItem -Recurse | Get-Member
Get-ChildItem -Recurse | Where-Object HasPrivateKey -eq $true
# be careful here with data types: "false" is still _true_
# use the boolean variable:        $false if you want false


########### VARIABLES

# bad name
$a = 'anything here'
# good name, because it tells you what is inside
$AllServices = Get-Service

New-Variable -Name c -Value 'something' -Option Constant
$c = 'and now something else' # this will fail!

# automatic data types
$a = 'something'
$a | Get-Member
$a.GetType()
$b = '4'
$x = 3
$pi = 3.141592
$y = 2

# but be careful...
$y + $b
$b + $y

# setting and changing object type
[int]$z = '7'
$x -as [string]
($x -as [string]).GetType()
$pi -as [int]

# also remember variable scope
# sample file included in ZIP to be placed in current directory
.\scope.ps1
# what is the value of A now?
$a


########### COLLECTIONS

$array = 1, 2, 34, 555, 678, 9000
$array
$array[0]    # 1st element
$array[2]    # 3rd element
$array.Count # every collection has a Count property.
$array[$array.Count -1]
$array[-2]   # Cool! You can index from end.
$array[20]   # NOT cool. No out-of-bounds errors.

# collections typically show up as the type of object that is inside
$array | Get-Member
# you can see that this is an array by using a method
$array.GetType()

# easy way to loop through elements of an array
$array | ForEach-Object { Write-Host -f Yellow -b Black "The number $_" }
# side-note: be careful with variables in strings - PowerShell is not greedy
$services | ForEach-Object { Write-Host -f Yellow -b Black "The service name $_.DisplayName" }
# the fix:
$services | ForEach-Object { Write-Host -f Yellow -b Black "The service name $($_.DisplayName)" }

# if you need to loop through an array to look for an element, use these operators instead
3 -in $array # false in our case
$array -contains 34 # true

$emptyArray = @()

$twoDimensional = @('A1','A2'),@('B1','B2')
$twoDimensional[1][0]

# expensive memory-wise
$array = $array + 100000
# because it creates a copy of the data in memory
# as an array is of a fixed size
$array.IsFixedSize

# uses less memory but requires more work.
$list  = New-Object System.Collections.ArrayList
$list.IsFixedSize # no, it's flexible
$list.Add(1)
$list.Add(2)
$list.Add(34)
# etc...
$list
$list[0]

# hash tables
$hashTable = @{
    'Shape' = 'circle';
    'Color' = 'blue'
}
# are indexed by Key, not order
$hashTable['color']

$emptyHashTable = @{}


########### FLOW CONTROL

# FOR loop to count 1 to 10
for ($i = 1; $i -le 10; $i++) { 
    $i   
}

# same thing with a DO..WHILE loop
$i = 1
do {
    $i
    $i++    
} while ($i -le 10)

# but while loops don't tend to use counters
# here instead, Read-Host can be used to gather user input
do {
  Write-Host 'Stuff happens here...'
} while ((Read-Host -Prompt 'Type Q to quit') -ne 'Q')

# conditional IF statements
if ($Light -eq 'Green') {
    # WALK
} elseif ($Light.Blinking -eq $true) {
    # finish crossing
} else {
    # DON'T WALK
}


########### REPOSITORY

# WMI and WinRM cmdlets both do the same thing using different protocols
Get-Command -Noun WMI*, CIM*

Get-Help Get-WmiObject -ShowWindow

# search for classes
Get-WmiObject -List -Class Win32*BIOS*
# get instance of that class
Get-WmiObject -Class Win32_BIOS
# get instance and see all its properties
# remember that PowerShell typically hides things from you
Get-WmiObject -Class Win32_BIOS | fl -Property *


########### REMOTING

# getting credentials
$creds = Get-Credential -Message 'Credentials for GDC-DC'
$creds

# Remote WMI command
Get-WmiObject -Class Win32_Service -ComputerName 10.11.12.13 -Credential $creds

# remote WinRM command, first setting up a reusable session
New-CimSession -ComputerName 10.11.12.13 -Credential $creds
Get-CimInstance -ClassName Win32_Service -CimSession (Get-CimSession -Id 1)

# PowerShell Remoting to send ANY command to another system
Enter-PSSession -ComputerName 10.11.12.13 -Credential $creds
Invoke-Command { Get-WindowsEdition -online } -computerName 10.11.12.13 -Credential $creds


########### SCRIPT SECURITY

Get-ExecutionPolicy
Get-ExecutionPolicy -List
Set-ExecutionPolicy -ExecutionPolicy AllSigned -WhatIf
# sample file included in ZIP to be placed in current directory
Get-AuthenticodeSignature .\SampleSignedScript.ps1

# to sign a script, first find a code-signing certificate
Get-ChildItem cert:\ -Recurse -CodeSigningCert
