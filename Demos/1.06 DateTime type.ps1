#           _          _
#        __| |____ ___| |__
#       / _  |__  / __| '_ \           Script: '1.06 DateTime type.ps1'
#      | (_| |(_| \__ \ | | |          Author: Paul 'Dash'
#       \__,_\__,_|___/_| |_(_)        E-mail: paul@dash.training
#       T  R  A  I  N  I  N  G


# DateTime creation, conversion, formatting and edge-case examples.

# Current date/time
Get-Date

Get-Date | Get-Member -MemberType Properties

# Basic properties
(Get-Date).Year              # Year only
(Get-Date).Month             # Month (1-12)
(Get-Date).Day               # Day of month
(Get-Date).DayOfWeek         # Enum: Monday, Tuesday, etc.
(Get-Date).DayOfYear         # 1-366

### Calculate time difference
$birthDate = [datetime]'1990-05-15'
(Get-Date) - $birthDate
New-TimeSpan -Start $birthDate -End (Get-Date)

# Add / Subtract
Get-Date | Get-Member -MemberType Methods

(Get-Date).AddHours(3)       # Three hours from now
(get-date).Subtract(...)     # ...is difficult to use, so...
(Get-Date).AddDays(-1)       # Yesterday

## Creating DateTime values

# Direct cast from an ISO-like string
[datetime]"2018-10-02 11:55:00"

# Natural language parse examples
[datetime]"October 2 2018 11:55 AM"

# Simple short-date cast (culture sensitive!)
[datetime]"4/01/2019"                   # Interpreted using current culture

# [ADVANCED] Construct from components (Year,Month,Day[,Hour,Minute,Second])
[datetime]::new(2023,6,8)               # 2023-06-08 00:00:00
[datetime]::new(2023,6,8,14,30,0)       # 2023-06-08 14:30:00

# ParseExact requires the format string to match the input
[datetime]::ParseExact('02/10/2018','dd/MM/yyyy',$null)
[datetime]::ParseExact('2018-10-02','yyyy-MM-dd',$null)

# [ADVANCED] TryParse avoids exceptions and returns success boolean
$dtRef = [ref]$null
if ([datetime]::TryParse('02/10/2018',[ref]$dtRef)) { $dtRef.Value } else { 'Parse failed' }

### Culture-sensitive parsing examples
# Ambiguous format: is 02/10/2018 Feb 10 or Oct 2? Depends on culture
[System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-GB'
[datetime]'02/10/2018'                   # UK => 2 Oct 2018
[System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
[datetime]'02/10/2018'                   # US => Feb 10 2018

## Writing DateTime values

### Formatting output
Get-Date -Format 'yyyy-MM-dd HH:mm:ss'   # Custom format via Get-Date
([datetime]::UtcNow).ToString('o')       # Round-trip (ISO 8601) format

### Useful helper: display common .NET format specifiers
function Get-DateTimeFormat {
    $dt = Get-Date
    $specs = @('d','D','f','F','g','G','M','m','o','O','R','r','s','t','T','u','U','Y','y')
    foreach ($s in $specs) { [PSCustomObject]@{Specifier = $s; Example   = $dt.ToString($s) } }
}
Get-DateTimeFormat | Format-Table -AutoSize

## Time zones and offsets

# DateTime vs DateTimeOffset: offsets preserve zone info
$local = Get-Date
$utc   = $local.ToUniversalTime()
$utc   # Local time converted to UTC (loses original zone info)

[DateTimeOffset]::Now                    # Current time with offset

### DateTimeKind and conversions
$t1 = [datetime]::new(2026,1,1)
$t1.Kind                                 # Unspecified by default
$t2 = [datetime]::SpecifyKind($t1,[System.DateTimeKind]::Utc)
$t2.Kind                                 # Now it's Utc
$t3 = [datetime]::SpecifyKind($t1,[System.DateTimeKind]::Local)
$t3.Kind                                 # Now it's Local

### Unix epoch conversions
[DateTimeOffset]::FromUnixTimeSeconds(0).UtcDateTime   # 1970-01-01 UTC

### Ticks and precision
$now = Get-Date
$now.Ticks                               # 100-nanosecond ticks since 0001-01-01

# FileTime, Common in Windows API, uses a similar tick count but starts at 1601-01-01 UTC.
$fileTime = 132537600000000000
[datetime]::FromFileTimeUtc($fileTime)   # 2020-01-01 00:00:00 UTC
[datetime]::FromFileTimeUtc($fileTime).ToFileTimeUtc()  # round-trip back to FILETIME ticks

# Parse WMI-style date/time strings
$bios = Get-WMIObject Win32_BIOS
$bios.ReleaseDate                        # Raw WMI datetime string
# available up to PowerShell 5.1
$bios | gm -MemberType Methods
$bios.ConvertToDateTime($bios.ReleaseDate)
# better: use .NET helper available in all versions
[Management.ManagementDateTimeConverter]::ToDateTime($bios.ReleaseDate)

## Edge cases and Issues

### Invalid formats
try {
    [datetime]'not a date'
} catch {
    Write-Host "Invalid cast error: $($_.Exception.Message)" -f White -b Red
}

### Invalid dates (e.g., Feb 29 on non-leap year)
try {
    [datetime]::new(2019,2,29)
} catch {
    Write-Host "Invalid date error: $($_.Exception.Message)" -f White -b Red
}

### [ADVANCED] Daylight Saving Time
# When clocks fall back, the same local wall-clock time can occur twice.
# A plain local DateTime has no offset, so 2023-11-05 01:30:00 is ambiguous.
$ambiguousLocal = [datetime]::Parse('2023-11-05 01:30:00')
Write-Host "Ambiguous local DateTime: $ambiguousLocal"
# so...
# Use DateTimeOffset with an explicit offset to disambiguate.
$firstOccurrence  = [datetimeoffset]::new(2023,11,5,1,30,0,[timespan]'-04:00')  # EDT
$secondOccurrence = [datetimeoffset]::new(2023,11,5,1,30,0,[timespan]'-05:00')  # EST
Write-Host "First occurrence  → UTC: $($firstOccurrence.UtcDateTime)"
Write-Host "Second occurrence → UTC: $($secondOccurrence.UtcDateTime)"

## Other stuff

### Leap year check helper
[datetime]::IsLeapYear(2024)   # True for 2024
[datetime]::IsLeapYear(2026)   # False for 2026

### Round up to 15 minutes
$now       = Get-Date
$now       = $now.AddSeconds(-($now.Second)) # reset seconds to zero
$interval  = 15
$remainder = $now.Minute % $interval
if ($remainder -ne 0) {
    $now.AddMinutes($interval - $remainder)
} else {
    $now
}

### Measure code execution time
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
Start-Sleep -Milliseconds 250
$stopwatch.Stop()
Write-Host "Elapsed: $($stopwatch.Elapsed.TotalMilliseconds) ms"
