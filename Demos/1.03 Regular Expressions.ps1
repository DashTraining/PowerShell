#           _          _
#        __| |____ ___| |__
#       / _  |__  / __| '_ \           Script: '1.03 Regular Expressions.ps1'
#      | (_| |(_| \__ \ | | |          Author: Paul 'Dash'
#       \__,_\__,_|___/_| |_(_)        E-mail: paul@dash.training
#       T  R  A  I  N  I  N  G

# Regular expressions (REGEX) in PowerShell.
#
# Resources:
# http://rubular.com/
# http://regexlib.com/Search.aspx?AspxAutoDetectCookieSupport=1


# 1. Simple matches

# Match a simple string
'PowerShell'   -match 'Shell'

# Match one or more digits
'Answer is 42' -match '\d+'
$Matches # variable returns what actually matched

# Match any characters
'Deep Thought says the answer is 42' -match 'answer is .*'
$Matches

# Match a whole word
'PowerShell is a command shell' -match '\bshell\b'
$Matches

# Match a line: letters, then a dash, then digits
'Catch-22' -match '^[A-Za-z]+-\d+$'

# Match a date-like value with a little structure
'2026-06-14'   -match '^\d{4}-\d{2}-\d{2}$'


# 2. Capture groups

# Non-capturing group (?:...) for repeated pattern
# Credit card number
$creditCardPattern = '^(?:\d[ -]?){13,16}$'
'4111 1111 1111 1111' -match $creditCardPattern
$Matches

# Optional groups use (...)? and capture matched parts of the input
# Alternations use | to define alternative matches
# Version numbers: parts with numbers and words
$versionPattern = '^(\d+)\.(\d+)(?:\.(\d+))?(?:-(alpha|beta|rc\d+))?$'
'7.4.1-beta' -match $versionPattern
$Matches

# Named groups make the captured values easier to use later
# Dates
$datePattern = '^(?<Year>\d{4})[./-](?<Month>\d{1,2})[./-](?<Day>\d{1,2})$'
'1985/3/15' -match $datePattern
$Matches
$Matches['Year']
$Matches['Month']
$Matches['Day']


# 3. More real-world patterns

# Phone numbers: character classes, optional dashes
$phonePattern = '^(\d{3})[-.]?(\d{3})[-.]?(\d{4})$'
'555-867-5309' -match $phonePattern
$Matches['1']  # area code
$Matches['2']  # exchange
$Matches['3']  # line number

# Hex color codes: alternation with {x} quantifier.
$colorPattern = '^#([0-9A-Fa-f]{6}|[0-9A-Fa-f]{3})$'
'#FF5733' -match $colorPattern
'#abc' -match $colorPattern

# IP addresses: character classes [0-9] and quantifier limits {1,3}
# This simple version doesn't validate the ranges, but shows the structure
$ipPattern = '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
'192.168.1.1' -match $ipPattern
$Matches

# Simple key=value pairs with named groups.
$keyValuePattern = '^(?<Key>\w+)=(?<Value>.*)$'
'Mode=Expert' -match $keyValuePattern
$Matches['Key']
$Matches['Value']
# For this exact usage, consider the ConvertFrom-StringData cmdlet


# 4. Direct [regex]::Match() for richer match information

# The .NET Regex class provides a full match object with properties and methods
# Use this when you need more detail than -match provides

# Match with positional capture groups
$m1 = [regex]::Match('Catch-22', '([A-Za-z]+)-(\d+)')
$m1
$m1.Groups

# Complex patterns become easier to read with named groups
$uriPattern = '^(https?)://(?<Host>[A-Za-z0-9.-]+)(?::(?<Port>\d{1,5}))?(?<Path>/[A-Za-z0-9./_-]*)?(?:\?(?<Query>[A-Za-z0-9=&_-]+))?$'
$m2 = [regex]::Match('https://example.com:8080/docs/powershell/regex?level=advanced&topic=groups', $uriPattern)
$m2.Groups['Host'].Value
$m2.Groups['Path'].Value
$m2.Groups['Query'].Value


# 5. The Regex Horror Show

# Regex can become unreadable very quickly, even when technically "correct"
# This is RFC5322 email validation, but you probably don't want to memorize it
$RFC5322 = "(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|`"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*`")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"
'paul@pauldash.com' -match $RFC5322
