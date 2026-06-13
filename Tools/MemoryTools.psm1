#           _          _
#        __| |____ ___| |__
#       / _  |__  / __| '_ \           Script: 'MemoryTools.psm1'
#      | (_| |(_| \__ \ | | |          Author: Paul 'Dash'
#       \__,_\__,_|___/_| |_(_)        E-mail: paul@dash.training
#       T  R  A  I  N  I  N  G

# Module 'MemoryTools'


<#
.SYNOPSIS
    Measures peak memory usage of a script block or script file, similar to Measure-Command.

.DESCRIPTION
    Executes the provided code while continuously monitoring several memory counters.
    Returns the maximum (peak) values observed during execution using a background job
    for improved isolation.

.PARAMETER ScriptBlock
    The script block to execute and measure.

.PARAMETER FilePath
    Path to a .ps1 script file to execute and measure.

.PARAMETER PollingInterval
    How frequently (in milliseconds) to sample memory counters. Lower values are more accurate but use more CPU.
    Default is 250ms.

.OUTPUTS
    PSCustomObject with:
    - MaxWorkingSetBytes
    - MaxPrivateBytes
    - MaxPagedBytes
    - MaxVirtualBytes

.NOTES
    Output Properties:
    - MaxWorkingSetBytes   : Peak physical memory used by the process (most relevant for RAM usage)
    - MaxPrivateBytes      : Peak private memory committed by the process (exclusive to this process)
    - MaxPagedBytes        : Peak paged memory (can be swapped to disk)
    - MaxVirtualBytes      : Peak virtual address space reserved/used
    - MaxNonPagedBytes     : Peak non-pageable kernel memory (system-critical)
    - MaxWorkingSetMB, MaxPrivateMB, ... : Same values converted to megabytes for readability
    - DurationMs           : Total execution time in milliseconds

    All "Max*" values represent maximums observed during polling. For more accurate results, consider lowering the PollingInterval, but be aware of increased CPU usage.

.EXAMPLE
$mem = Measure-MemoryUsage {
    1..500000 | ForEach-Object { [byte[]]::new(1024) }  # Simulate memory allocation
}
$mem | Format-List Max*MB, DurationMs

.EXAMPLE
Measure-MemoryUsage -FilePath "C:\Scripts\HeavyScript.ps1" -PollingInterval 100
#>
function Measure-MemoryUsage {
    [CmdletBinding(DefaultParameterSetName = 'ScriptBlock')]
    param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'ScriptBlock')]
        [ScriptBlock]$ScriptBlock,

        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$FilePath,

        [Parameter()]
        [int]$PollingInterval = 250   # Default sampling rate - balance between accuracy and overhead
    )

    # Determine the code to execute based on parameter set
    if ($PSCmdlet.ParameterSetName -eq 'File') {
        # Dot-source the script file so it runs in the job's scope
        $code = [ScriptBlock]::Create(". '$FilePath'")
    } else {
        $code = $ScriptBlock
    }

    # Start a background job for isolation and monitoring
    $job = Start-Job -ScriptBlock {
        param([ScriptBlock]$CodeToRun, [int]$IntervalMs)

        # Get reference to current process
        $process = Get-Process -Id $PID

        # Initialize tracking with current peak values
        $maxStats = @{
            WorkingSet64  = $process.PeakWorkingSet64
            PrivateBytes  = $process.PrivateMemorySize64
            PagedBytes    = $process.PeakPagedMemorySize64
            VirtualBytes  = $process.PeakVirtualMemorySize64
            NonPagedBytes = $process.PeakNonpagedSystemMemorySize64
        }

        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        # Execute the target code in a nested job so we can poll while it runs
        $runJob = Start-Job -ScriptBlock $CodeToRun

        # Polling loop - continuously sample memory while code is running
        while ($runJob.State -eq 'Running') {
            $process.Refresh()  # Update process counters

            # Update each maximum if a new high is observed
            if ($process.PeakWorkingSet64 -gt $maxStats.WorkingSet64) {
                $maxStats.WorkingSet64 = $process.PeakWorkingSet64
            }
            if ($process.PrivateMemorySize64 -gt $maxStats.PrivateBytes) {
                $maxStats.PrivateBytes = $process.PrivateMemorySize64
            }
            if ($process.PeakPagedMemorySize64 -gt $maxStats.PagedBytes) {
                $maxStats.PagedBytes = $process.PeakPagedMemorySize64
            }
            if ($process.PeakVirtualMemorySize64 -gt $maxStats.VirtualBytes) {
                $maxStats.VirtualBytes = $process.PeakVirtualMemorySize64
            }
            if ($process.PeakNonpagedSystemMemorySize64 -gt $maxStats.NonPagedBytes) {
                $maxStats.NonPagedBytes = $process.PeakNonpagedSystemMemorySize64
            }

            Start-Sleep -Milliseconds $IntervalMs
        }

        $stopwatch.Stop()

        # Clean up the inner job
        $runJob | Receive-Job -Wait -AutoRemoveJob | Out-Null

        # Final refresh after execution completes
        $process.Refresh()

        # Return rich object with both raw bytes and MB values
        [PSCustomObject]@{
            MaxWorkingSetBytes = $maxStats.WorkingSet64
            MaxPrivateBytes    = $maxStats.PrivateBytes
            MaxPagedBytes      = $maxStats.PagedBytes
            MaxVirtualBytes    = $maxStats.VirtualBytes
            MaxNonPagedBytes   = $maxStats.NonPagedBytes

            MaxWorkingSetMB    = [Math]::Round($maxStats.WorkingSet64 / 1MB, 2)
            MaxPrivateMB       = [Math]::Round($maxStats.PrivateBytes / 1MB, 2)
            MaxPagedMB         = [Math]::Round($maxStats.PagedBytes / 1MB, 2)
            MaxVirtualMB       = [Math]::Round($maxStats.VirtualBytes / 1MB, 2)
            MaxNonPagedMB      = [Math]::Round($maxStats.NonPagedBytes / 1MB, 2)

            DurationMs         = $stopwatch.Elapsed.TotalMilliseconds
        }
    } -ArgumentList $code, $PollingInterval

    # Receive and return the result from the monitoring job
    Receive-Job -Job $job -Wait -AutoRemoveJob
}
