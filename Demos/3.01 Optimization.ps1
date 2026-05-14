#Requires -Version 5

#
#        _| _ __|_           Script:  '3.01 Optimization.ps1'
#       (_|(_|_)| ) .        Author:  Paul 'Dash'
#      t r a i n i n g       Contact: paul@dash.training
#                            Created: 2016-12-04
#

break
<#
TALKING POINTS - Before trying to optimize, ask yourself:

0. Running it once? Do you need to optimize?
0A. Do you have time to optimize?
0B. Will optimizing make it unreadable?
0C. Has somebody done it before?
1. Use filtering as soon as possible
2. Try to not repeat "expensive" operations
3. Use the right collection type (array, arraylist, hash table)
4. Search text using REGEX or Convert-String / ConvertFrom-String
5. Do Start-Sleep to let other threads execute

#>



######################################## Piping Inefficiency
########################################
########################################
######################################## Looping
Clear-Host
(Measure-Command {

1..100000 | ForEach-Object { Write-Output $_ }

}).TotalMilliseconds

(Measure-Command {

foreach ($number in (1..10000)) { Write-Output $number }

}).TotalMilliseconds

(Measure-Command {

(1..10000).ForEach({Write-Output $_})

}).TotalMilliseconds


######################################## Cmdlet Parameters
Clear-Host
(Measure-Command {

1..1000000 | Get-Random

}).TotalMilliseconds

(Measure-Command {

Get-Random -Minimum 1 -Maximum 1000001

}).TotalMilliseconds


######################################## but... piping allows you to quit early
Clear-Host
(Measure-Command {

1..1000000 | Select-Object -First 1

}).TotalMilliseconds

(Measure-Command {

(1..1000000)[0]

}).TotalMilliseconds



######################################## Filtering
########################################
########################################
######################################## Cmdlet vs. Method
Clear-Host
(Measure-Command {
    1..100 | foreach {

        Get-Service | Where-Object {$_.Status -EQ 'Running'}

    }
}).TotalMilliseconds

(Measure-Command {
    1..100 | foreach {

        (Get-Service).where({$_.Status -EQ 'Running'})

    }
}).TotalMilliseconds



######################################## Array vs. Allocated Array vs. ArrayList
########################################
########################################
Clear-Host
$size = 10000

(Measure-Command {
    $array = @()
    for ($i = 0; $i -lt $size; $i++) {
        $array += $i
    }
}).TotalMilliseconds

(Measure-Command {
    $array = New-Object Int32[] $size
    for ($i = 0; $i -lt $size; $i++) {
        $array[$i] = $i
    }
}).TotalMilliseconds

(Measure-Command {
    $array = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $size; $i++) {
        $array.Add($i)
    }
}).TotalMilliseconds

(Measure-Command {
    $array = [System.Collections.Generic.List[Int32]]::new()
    for ($i = 0; $i -lt $size; $i++) {
        $array.Add($i)
    }
}).TotalMilliseconds



######################################## No Strings Attached
########################################
########################################

Clear-Host
(Measure-Command {

    [string]$string = ''
    for ($i = 1; $i -le 10000; $i++) {
        $string += 'na'
    }

}).TotalMilliseconds

(Measure-Command {

    $stringBuilder = New-Object System.Text.StringBuilder
    for ($i = 1; $i -le 10000; $i++) {
        $stringBuilder.Append('na')
    }

}).TotalMilliseconds

break
# Oh, reading the result requires you to:
$stringBuilder.ToString()



######################################## Stream IO
########################################
########################################
Clear-Host
$file = (Read-Host -Prompt "Full path to a large file")

(Measure-Command {

$content1 = Get-Content $file

}).TotalMilliseconds

(Measure-Command {

$content2 = ([System.IO.StreamReader] $file).ReadToEnd()
# You can also use this to read line-by-line,
# doing other processing in between,
# and decreasing memory usage.

}).TotalMilliseconds



######################################## Different types of nothing
######################################## "Into the Void"
########################################

Clear-Host
$data = 1..10
$data # This will redirect the object to Out-Default
break

Clear-Host
$data = 1..1000000

(Measure-Command {

    $data | Out-Null

}).TotalMilliseconds

(Measure-Command {

    $data > $null

}).TotalMilliseconds

(Measure-Command {

    $null = $data

}).TotalMilliseconds

(Measure-Command {

    [void]$data

}).TotalMilliseconds
