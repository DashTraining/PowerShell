#           _          _
#        __| |____ ___| |__
#       / _  |__  / __| '_ \           Script: '1.06 Split Operator.ps1'
#      | (_| |(_| \__ \ | | |          Author: Paul 'Dash'
#       \__,_\__,_|___/_| |_(_)        E-mail: paul@dash.training
#       T  R  A  I  N  I  N  G

# Demonstration of the PowerShell split operator.


# 1. Basic splitting
# Split a string into parts using a single delimiter.
$basic = 'cats,dogs,rain' -split ','
$basic
# Result is an array collection type.
$basic.GetType()


# 2. Limiting the number of splits
# Three values are produced. Subsequent commas are ignored.
$logLine = '2026-06-14 09:17:09,Error,Service running, but connection failed'

$logLine -split ',', 3


# 3. Assigning split results to variables
$cat, $dog, $weather = 'felix,spot,rain' -split ','
$cat
$dog
$weather


# 4. Assign records into objects
'Paul Dash,Trainer', 'Jane Smith,Admin' |
ForEach-Object {
    $name, $role = $_ -split ',', 2
    [pscustomobject]@{ Name = $name; Role = $role }
}


# 5. Scriptblock-based splitting
# Use a scriptblock when the split rule depends on the current character's position.
# Here we split on semicolons, but only when they are outside quotation marks.
$script:InsideQuotes = $false
$settings = 'Name = Paul Dash;Role = "Consultant;Trainer";Area = "Europe;Middle East;Asia-Pacific"' -split {
    if ($_ -eq '"') { $script:InsideQuotes = -not $script:InsideQuotes }
    -not $script:InsideQuotes -and $_ -eq ';'
}
$settings
# Clean up
Remove-Variable -Name InsideQuotes -Scope Script -ErrorAction SilentlyContinue
