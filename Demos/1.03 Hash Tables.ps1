#           _          _
#        __| |____ ___| |__
#       / _  |__  / __| '_ \           Script: '1.03 Hash Tables.ps1'
#      | (_| |(_| \__ \ | | |          Author: Paul 'Dash'
#       \__,_\__,_|___/_| |_(_)        E-mail: paul@dash.training
#       T  R  A  I  N  I  N  G

# Demonstration of hash tables.


# Reference:
# https://learn.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-hashtable


# 1. Create and inspect a hashtable
# A hashtable stores name/value pairs.
$settings = @{
    Shape = 'square'
    Color = 'yellow'
    Size  = 'small'
}

$settings
$settings.GetType().Name


# 2. Access keys and values
# You can inspect the keys, index by key, or read simple keys like properties.
$settings.Keys
$settings['Color']
$settings.Color

# You can add new keys or update existing ones.
$settings['Material'] = 'wood'
$settings['Color'] = 'red'
$settings

# 3. Ordered hashtables
# A normal hashtable does not guarantee display order, but [ordered] does.
[ordered]@{
    Shape = 'square'
    Color = 'yellow'
    Size  = 'small'
}


# 4. PSCustomObject creation
# A hashtable is often the easiest way to build an object with named properties.
$shape = [pscustomobject]@{
    Shape = 'circle'
    Color = 'blue'
    Size  = 'medium'
}

$shape
$shape | Get-Member -MemberType NoteProperty


# 5. Splatting
# Instead of writing a command with many parameters this way:
Get-CimInstance -Namespace root/cimv2 -ClassName Win32_Service -Filter "State='Running'" -Property Name, DisplayName, StartMode |
    Select-Object -First 5 Name, DisplayName, StartMode

# A hashtable can hold command parameters so the call is easier to read:
$serviceParams = @{
    Namespace = 'root/cimv2'
    ClassName = 'Win32_Service'
    Filter    = "State='Running'"
    Property  = 'Name', 'DisplayName', 'StartMode'
}

Get-CimInstance @serviceParams |
    Select-Object -First 5 Name, DisplayName, StartMode

# In addition, the parameter arguments can be updated using code:
$serviceParams.Filter = "StartMode='Auto'"

Get-CimInstance @serviceParams |
    Select-Object -First 5 Name, DisplayName, StartMode


# 6. A more complex hashtable
# Hash tables can contain more than just scalar values, like arrays and nested hash tables.
$shellProfile = @{
    Name        = 'Paul'
    Skills      = 'PowerShell', 'WPF', 'Regex'
    Preferences = @{
        Theme   = 'Dark'
        Font    = 'Cascadia Mono'
        Verbose = $true
    }
}

$shellProfile
$shellProfile.Preferences


# 7. Safer key checks
# Reading a missing key returns nothing, so ContainsKey() is safer when the key may not exist.
$settings['Weight']
$settings.ContainsKey('Color')
$settings.ContainsKey('Weight')


# 8. Enumerating key/value pairs
# You can loop over .Keys and do a lookup to retrieve the value for each key.
$settings.Keys |
    ForEach-Object { "{0} is the {1}" -f $_, $settings[$_] }

# GetEnumerator() is cleaner because each item already contains both the key and the value.
$settings.GetEnumerator() |
    ForEach-Object { "{1} is the {0}" -f $_.Key, $_.Value }


# 9. Serialization
# ConvertTo-Json is a practical way to serialize nested hashtable data.
$shellProfile
$shellProfile | ConvertTo-Json -Depth 3


# 10. Generic dictionaries
# Generic dictionaries are useful when you want specific key and value types.
$scores = [System.Collections.Generic.Dictionary[string,int]]::new()
$scores['Paul'] = 42
$scores['Jane'] = 101
$scores

$scores['Kate'] = 'zero'
$scores['Bob']  = 3.141592
$scores


# 11. Case sensitivity
# Normal PowerShell hashtables treat string keys as case-insensitive by default.
$settings['color']
$settings['COLOR']

# A generic dictionary can be created with a case-sensitive string comparer.
$caseSensitiveSettings = [System.Collections.Generic.Dictionary[string,string]]::new(
    [System.StringComparer]::Ordinal
)
$caseSensitiveSettings['Color'] = 'blue'
$caseSensitiveSettings['color'] = 'green'
$caseSensitiveSettings
