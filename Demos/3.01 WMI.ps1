#
#        _| _ __|_           Script:  '3.01 WMI.ps1'
#       (_|(_|_)| ) .        Author:  Paul 'Dash'
#      t r a i n i n g       Contact: paul@dash.training
#


# More advanced WMI / CIM examples with classes that are slow, surprising, or awkward.


### 1. Software inventory: avoid Win32_Product

# Bad, as it causes MSIs to enumerate and may cause them to try to "Fix" their installations.
# Get-WmiObject -Class Win32_Product

# Better: read uninstall information from the registry instead.
Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall |
    Get-ItemProperty |
    Where-Object DisplayName |
    Select-Object DisplayName, DisplayVersion, Publisher, UninstallString


### 2. Weird but useful: method-only registry provider

# StdRegProv is unusual because to use it, you need to call methods instead of just reading instances.
$registryClass = Get-CimClass -Namespace root\default -ClassName StdRegProv
$registryClass.CimClassMethods.Keys

# Read the ProgramFilesDir value from HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion.
$registryArgs = @{
    hDefKey     = [uint32]2147483650 # HKEY_LOCAL_MACHINE
    sSubKeyName = 'SOFTWARE\Microsoft\Windows\CurrentVersion'
    sValueName  = 'ProgramFilesDir'
}
Invoke-CimMethod -Namespace root\default -ClassName StdRegProv -MethodName GetStringValue -Arguments $registryArgs


### 3. Easy to misuse: Win32_NTLogEvent

# This class can be painfully slow to query.
Get-CimInstance -ClassName Win32_NTLogEvent -Filter "Logfile = 'System' AND Type = 'Error'" |
    Select-Object -First 5 SourceName, EventCode, TimeGenerated, Message

# Compare that with the event log cmdlet.
Get-WinEvent -FilterHashtable @{LogName = 'System'; Level = 2} |
    Select-Object -First 5 ProviderName, Id, TimeCreated, Message


### 4. Good WinRM / CIM-only conversation: MSFT_NetFirewallRule

# While cmdlets are sometimes just wrappers around WMI/CIM, like for firewall rules...
Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetFirewallRule |
    Select-Object -First 5 DisplayName, Enabled, Direction, Action

# ...like can be seen in the TypeName here...
Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetFirewallRule |
    Select-Object -First 1 | Get-Member | Out-string -Stream | Select-string "TypeName:"
# ...and here...
Get-NetFirewallRule |
    Select-Object -First 1 | Get-Member | Out-string -Stream | Select-string "TypeName:"

# ...but they do make sense as they produce frendlier output.
Get-NetFirewallRule |
    Select-Object -First 5 DisplayName, Enabled, Direction, Action


### 5. Working with associators and references

# Associators show objects related to a given instance, based on an association class.
$disk = Get-CimInstance -ClassName Win32_DiskDrive | Select-Object -First 1
$disk | Select-Object DeviceID, Model

Get-CimAssociatedInstance -InputObject $disk -Association Win32_DiskDriveToDiskPartition |
    Select-Object DeviceID, Type, Size

# References show the association instances themselves, which can contain additional data about the relationship.
Get-CimInstance -ClassName Win32_DiskDriveToDiskPartition |
    Where-Object { $_.Antecedent -match [regex]::Escape($disk.DeviceID) } |
    Select-Object Antecedent, Dependent

# Another associator example. A network adapter does not contain IP address information directly.
$adapter = Get-CimInstance -ClassName Win32_NetworkAdapter -Filter "NetEnabled = True" |
    Select-Object -First 1

# IPAddress is null here
$adapter | Select-Object Name, DeviceID, IPAddress

# But we can get the associated network adapter settings, which include IP information.
Get-CimAssociatedInstance -InputObject $adapter -Association Win32_NetworkAdapterSetting |
    Select-Object Description, DHCPEnabled, IPAddress


### 6. Working with Events

# Indication events are invoked when something happens, but to get them you need a subscription.
# This is different from polling a class repeatedly to detect changes.
$sourceIdentifier = 'WmiDemo.ProcessStart'
$launchedProcess = $null

# Clean up any leftover subscription or queued event from an earlier run.
Unregister-Event -SourceIdentifier $sourceIdentifier -ErrorAction SilentlyContinue
Remove-Event -SourceIdentifier $sourceIdentifier -ErrorAction SilentlyContinue

try {
    # Create a long-running subscription for Win32_ProcessStartTrace.
    # Each process start will generate an event while the subscription is active.
    Register-CimIndicationEvent -Namespace root/cimv2 `
                                -ClassName Win32_ProcessStartTrace `
                                -SourceIdentifier $sourceIdentifier `
                                -ErrorAction Stop
}
catch {
    "Could not register the CIM event in this session: $($_.Exception.Message)"
    return
}

Write-Host "Process start subscription is active." -ForegroundColor Yellow
Write-Host "Start one or more processes and each event will be displayed." -ForegroundColor Yellow
Write-Host "Press Ctrl+C to stop the demo and remove the event handler." -ForegroundColor DarkYellow

trap [System.Management.Automation.PipelineStoppedException] {
    Write-Host 'Process event loop stopped by user.' -ForegroundColor Yellow
    break
}

while ($true) {
    $event = Wait-Event -SourceIdentifier $sourceIdentifier -Timeout 60

    if (-not $event) {
        Write-Host 'Still waiting for process start events...' -ForegroundColor DarkGray
        continue
    }

    # The interesting payload is in the CIM event's SourceEventArgs.NewEvent property
    $newEvent = $event.SourceEventArgs.NewEvent

    [pscustomobject]@{
        ProcessName     = $newEvent.ProcessName
        ProcessID       = $newEvent.ProcessID
        ParentProcessID = $newEvent.ParentProcessID
        TimeCreated     = [datetime]::FromFileTime($newEvent.TIME_CREATED)
    } | Format-Table -AutoSize

    # Remove the event from the queue so it is not processed again.
    Remove-Event -SourceIdentifier $sourceIdentifier -ErrorAction SilentlyContinue
}

# Final cleanup when the loop ends normally or after Ctrl+C.
Unregister-Event -SourceIdentifier $sourceIdentifier -ErrorAction SilentlyContinue
Remove-Event -SourceIdentifier $sourceIdentifier -ErrorAction SilentlyContinue
