#           _          _
#        __| |____ ___| |__
#       / _  |__  / __| '_ \           Script: 'HyperVTools.psm1'
#      | (_| |(_| \__ \ | | |          Author: Paul 'Dash'
#       \__,_\__,_|___/_| |_(_)        E-mail: paul@dash.training
#       T  R  A  I  N  I  N  G

# Module 'HyperVTools'
# associated with manifest 'HyperVTools.psd1'


# .SYNOPSIS
# List the configuration files for VMs on the local Hyper-V host.
function Get-VMConfigurationFile {
    [CmdletBinding(DefaultParameterSetName='ByName')]
    param(
        [Parameter(ParameterSetName='ByName')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(1, 255)]
        [ValidatePattern('^(?!.*[\\/:\<\>\|"\x00-\x1F])(?!.*[ .]$).+$')]
        [string]$VMName = '*',

        [Parameter(ParameterSetName='ById')]
        [ValidatePattern('^[0-9A-Fa-f-]{36}$')]
        [string]$VMId,

        [switch]$OnlyMissing
    )

    $hostVmPath = (Get-VMHost).VirtualMachinePath
    $realizedSettings = Get-CimInstance -Namespace root\virtualization\v2 -ClassName MSVM_VirtualSystemSettingData |
        Where-Object VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized' |
        Select-Object ElementName,
                      VirtualSystemIdentifier,
                      @{N='ConfigurationPath';E={[System.IO.Path]::GetFullPath([System.IO.Path]::Combine($_.ConfigurationDataRoot, $_.ConfigurationFile))}}

    $realizedVmIds = $realizedSettings |
        ForEach-Object { $_.VirtualSystemIdentifier.ToUpperInvariant() }

    $allVms = Get-CimInstance -Namespace root\virtualization\v2 -ClassName MSVM_ComputerSystem |
        Where-Object Caption -eq 'Virtual Machine' |
        Where-Object {
            if ($PSCmdlet.ParameterSetName -eq 'ById') {
                $_.Name.ToUpperInvariant() -eq $VMId.ToUpperInvariant()
            } else {
                $_.ElementName -like $VMName
            }
        }

    $results = foreach ($vm in $allVms) {
        $expectedPath = [System.IO.Path]::GetFullPath(
            [System.IO.Path]::Combine($hostVmPath, 'Virtual Machines', ($vm.Name.ToUpperInvariant() + '.vmcx'))
        )
        $realizedSetting = $realizedSettings |
            Where-Object VirtualSystemIdentifier -eq $vm.Name.ToUpperInvariant() |
            Select-Object -First 1
        $hasRealizedConfiguration = $vm.Name.ToUpperInvariant() -in $realizedVmIds
        $resolvedConfigurationPath = if ($realizedSetting) {
            $realizedSetting.ConfigurationPath
        } else {
            $expectedPath
        }

        [pscustomobject]@{
            ElementName               = $vm.ElementName
            VMId                      = $vm.Name.ToUpperInvariant()
            Status                    = $vm.Status
            StatusDescriptions        = $vm.StatusDescriptions
            ConfigurationPath         = $expectedPath
            ConfigurationFileExists   = Test-Path -LiteralPath $resolvedConfigurationPath
        }
    }

    if ($OnlyMissing) {
        $results | Where-Object { -not $_.ConfigurationFileExists }
    } else {
        $results
    }
}

# .SYNOPSIS
# Retrieves the parent chain of a VHD or VHDX file, along with the VHD information for the leaf disk.
function Get-VHDParentChain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Virtual disk '$Path' does not exist."
    }

    $resolvedPath = (Resolve-Path -LiteralPath $Path).Path
    $chain = [System.Collections.Generic.List[string]]::new()
    $currentPath = $resolvedPath

    while ($currentPath) {
        if (-not (Test-Path -LiteralPath $currentPath)) {
            throw "Virtual disk chain is missing '$currentPath'."
        }

        $chain.Add($currentPath)
        $vhd = Get-VHD -Path $currentPath -ErrorAction Stop

        if ([string]::IsNullOrWhiteSpace($vhd.ParentPath)) {
            break
        }

        $currentPath = (Resolve-Path -LiteralPath $vhd.ParentPath -ErrorAction Stop).Path
    }

    [pscustomobject]@{
        LeafPath   = $resolvedPath
        ParentChain = $chain.ToArray()
        VhdInfo    = $vhd
    }
}

function getVMGenerationFromDisk {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $mountedVhd = $null

    try {
        $mountedVhd = Mount-VHD -Path $Path -ReadOnly -Passthru -ErrorAction Stop
        $disk = Get-Disk -Number $mountedVhd.DiskNumber -ErrorAction Stop
        $partitions = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue

        if ($disk.PartitionStyle -eq 'GPT') {
            $efiPartition = $partitions | Where-Object {
                $_.GptType -eq '{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}'
            } | Select-Object -First 1

            if ($efiPartition) {
                return 2
            }
        }

        if ($disk.PartitionStyle -eq 'MBR') {
            $activePartition = $partitions | Where-Object IsActive | Select-Object -First 1
            if ($activePartition) {
                return 1
            }
        }

        return 2
    }
    finally {
        if ($mountedVhd) {
            Dismount-VHD -Path $Path -ErrorAction SilentlyContinue
        }
    }
}

function selectVMRecoverySwitch {
    [CmdletBinding()]
    param(
        [string]$SwitchName
    )

    if ($SwitchName) {
        $switch = Get-VMSwitch -Name $SwitchName -ErrorAction Stop
        return $switch.Name
    }

    $switches = Get-VMSwitch | Sort-Object Name

    if (-not $switches) {
        return $null
    }

    # List available switches with indices for selection
    '0: No network adapter' | Write-Host
    for ($i = 0; $i -lt $switches.Count; $i++) {
        '{0}: {1} ({2})' -f ($i + 1), $switches[$i].Name, $switches[$i].SwitchType | Write-Host
    }

    do {
        $selection = Read-Host -Prompt 'Choose a switch for the recovered VM'
    } until ($selection -match '^\d+$' -and [int]$selection -ge 0 -and [int]$selection -le $switches.Count)

    if ([int]$selection -eq 0) {
        return $null
    }

    $switches[[int]$selection - 1].Name
}

function replaceByteSequence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [byte[]]$Bytes,

        [Parameter(Mandatory)]
        [byte[]]$Find,

        [Parameter(Mandatory)]
        [byte[]]$Replace
    )

    if ($Find.Length -ne $Replace.Length) {
        throw 'Replacement sequences must be the same length.'
    }

    for ($i = 0; $i -le $Bytes.Length - $Find.Length; $i++) {
        $match = $true

        for ($j = 0; $j -lt $Find.Length; $j++) {
            if ($Bytes[$i + $j] -ne $Find[$j]) {
                $match = $false
                break
            }
        }

        if ($match) {
            [System.Buffer]::BlockCopy($Replace, 0, $Bytes, $i, $Replace.Length)
            $i += $Find.Length - 1
        }
    }

    $Bytes
}

function updateVMBinaryIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [guid]$OldGuid,

        [Parameter(Mandatory)]
        [guid]$NewGuid,

        [Parameter(Mandatory)]
        [string]$OldName,

        [Parameter(Mandatory)]
        [string]$NewName
    )

    $bytes = [System.IO.File]::ReadAllBytes($Path)

    $patterns = @(
        @{ Find = $OldGuid.ToByteArray(); Replace = $NewGuid.ToByteArray() },
        @{ Find = [System.Text.Encoding]::ASCII.GetBytes($OldGuid.Guid.ToUpperInvariant()); Replace = [System.Text.Encoding]::ASCII.GetBytes($NewGuid.Guid.ToUpperInvariant()) },
        @{ Find = [System.Text.Encoding]::ASCII.GetBytes($OldGuid.Guid.ToLowerInvariant()); Replace = [System.Text.Encoding]::ASCII.GetBytes($NewGuid.Guid.ToLowerInvariant()) },
        @{ Find = [System.Text.Encoding]::Unicode.GetBytes($OldGuid.Guid.ToUpperInvariant()); Replace = [System.Text.Encoding]::Unicode.GetBytes($NewGuid.Guid.ToUpperInvariant()) },
        @{ Find = [System.Text.Encoding]::Unicode.GetBytes($OldGuid.Guid.ToLowerInvariant()); Replace = [System.Text.Encoding]::Unicode.GetBytes($NewGuid.Guid.ToLowerInvariant()) },
        @{ Find = [System.Text.Encoding]::UTF8.GetBytes($OldName); Replace = [System.Text.Encoding]::UTF8.GetBytes($NewName.PadRight($OldName.Length).Substring(0, $OldName.Length)) },
        @{ Find = [System.Text.Encoding]::Unicode.GetBytes($OldName); Replace = [System.Text.Encoding]::Unicode.GetBytes($NewName.PadRight($OldName.Length).Substring(0, $OldName.Length)) }
    )

    foreach ($pattern in $patterns) {
        $bytes = Replace-ByteSequence -Bytes $bytes -Find $pattern.Find -Replace $pattern.Replace
    }

    [System.IO.File]::WriteAllBytes($Path, $bytes)
}

function renameVMRecoveryArtifacts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RootPath,

        [Parameter(Mandatory)]
        [guid]$OldGuid,

        [Parameter(Mandatory)]
        [guid]$NewGuid,

        [Parameter(Mandatory)]
        [string]$OldName,

        [Parameter(Mandatory)]
        [string]$NewName
    )

    $oldGuidUpper = $OldGuid.Guid.ToUpperInvariant()
    $newGuidUpper = $NewGuid.Guid.ToUpperInvariant()

    Get-ChildItem -LiteralPath $RootPath -Recurse -File | ForEach-Object {
        Update-VMBinaryIdentity -Path $_.FullName -OldGuid $OldGuid -NewGuid $NewGuid -OldName $OldName -NewName $NewName
    }

    Get-ChildItem -LiteralPath $RootPath -Recurse -File |
        Sort-Object FullName -Descending |
        ForEach-Object {
            if ($_.Name -match [regex]::Escape($oldGuidUpper)) {
                $newFileName = $_.Name -replace [regex]::Escape($oldGuidUpper), $newGuidUpper
                Rename-Item -LiteralPath $_.FullName -NewName $newFileName
            }
        }

    Get-ChildItem -LiteralPath $RootPath -Recurse -Directory |
        Sort-Object FullName -Descending |
        ForEach-Object {
            if ($_.Name -match [regex]::Escape($oldGuidUpper)) {
                $newDirectoryName = $_.Name -replace [regex]::Escape($oldGuidUpper), $newGuidUpper
                Rename-Item -LiteralPath $_.FullName -NewName $newDirectoryName
            }
        }
}

# .SYNOPSIS
# Repairs a broken VM configuration by creating a temporary scaffold VM, patching the configuration files with the original VM's identity, and re-registering the VM with Hyper-V.
function Repair-VMConfigurationFile {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High', DefaultParameterSetName='ByName')]
    param(
        [Parameter(ParameterSetName='ByName')]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(1, 255)]
        [ValidatePattern('^(?!.*[\\/:\<\>\|"\x00-\x1F])(?!.*[ .]$).+$')]
        [string]$VMName = '*',

        [Parameter(ParameterSetName='ById')]
        [ValidatePattern('^[0-9A-Fa-f-]{36}$')]
        [string]$VMId,

        [Parameter(Mandatory)]
        [string]$VhdPath,

        [string]$SwitchName
    )

    $brokenVmCandidates = if ($PSCmdlet.ParameterSetName -eq 'ById' -and $VMId) {
        Get-VMConfigurationFile -VMId $VMId -OnlyMissing
    } else {
        Get-VMConfigurationFile -VMName $VMName -OnlyMissing
    }

    if (-not $brokenVmCandidates) {
        throw 'No broken VMs matched the specified filter.'
    }

    $brokenVmSelection = @($brokenVmCandidates)

    if ($brokenVmSelection.Count -gt 1) {
        'Multiple broken VMs matched:' | Write-Host
        for ($i = 0; $i -lt $brokenVmSelection.Count; $i++) {
            '{0}: {1} [{2}]' -f ($i + 1), $brokenVmSelection[$i].ElementName, $brokenVmSelection[$i].VMId | Write-Host
        }
        'A: Recover all matched VMs' | Write-Host

        do {
            $selection = Read-Host -Prompt 'Choose a VM number or A for all'
        } until ($selection -match '^(?i:a|\d+)$' -and (($selection -match '^(?i:a)$') -or ([int]$selection -ge 1 -and [int]$selection -le $brokenVmSelection.Count)))

        if ($selection -match '^(?i:a)$') {
            $brokenVmSelection = @($brokenVmSelection)
        } else {
            $brokenVmSelection = @($brokenVmSelection[[int]$selection - 1])
        }
    }

    foreach ($brokenVm in $brokenVmSelection) {
        $originalVmName = $brokenVm.ElementName
        $originalVmId = [guid]$brokenVm.VMId
    $hostPaths = Get-VMHost
    $hostVmPath = $hostPaths.VirtualMachinePath
        $expectedConfigurationPath = $brokenVm.ConfigurationPath

        $diskChain = Get-VHDParentChain -Path $VhdPath
        $generation = getVMGenerationFromDisk -Path $diskChain.LeafPath
        $selectedSwitch = Select-VMRecoverySwitch -SwitchName $SwitchName

        $recoveryRoot = Join-Path -Path $hostVmPath -ChildPath ("Recovery-{0}" -f $originalVmId.Guid.ToUpperInvariant())
        $scaffoldRoot = Join-Path -Path $recoveryRoot -ChildPath 'Scaffold'
        $patchedRoot = Join-Path -Path $recoveryRoot -ChildPath 'Patched'
        $temporaryVmName = 'Recovery-{0}' -f ([guid]::NewGuid().Guid)

        $summary = [pscustomobject]@{
            VMName                    = $originalVmName
            VMId                      = $originalVmId.Guid.ToUpperInvariant()
            ExpectedConfigurationPath = $expectedConfigurationPath
            Generation                = $generation
            LeafDiskPath              = $diskChain.LeafPath
            ParentChain               = $diskChain.ParentChain
            SwitchName                = $selectedSwitch
            RecoveryWorkspace         = $recoveryRoot
            Registered                = $false
        }

        if (-not $PSCmdlet.ShouldProcess($originalVmName, 'Create scaffold VM, patch config files, and re-register the VM')) {
            $summary
            continue
        }

        New-Item -ItemType Directory -Path $scaffoldRoot, $patchedRoot -Force | Out-Null

        try {
            $newVmSplat = @{
                Name       = $temporaryVmName
                Path       = $scaffoldRoot
                Generation = $generation
                VHDPath    = $diskChain.LeafPath
            }

            if ($selectedSwitch) {
                $newVmSplat.SwitchName = $selectedSwitch
            }

            $scaffoldVm = New-VM @newVmSplat -ErrorAction Stop

            $scaffoldSettings = Get-CimInstance -Namespace root\virtualization\v2 -ClassName MSVM_VirtualSystemSettingData |
                Where-Object {
                    $_.VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized' -and
                    $_.VirtualSystemIdentifier -eq $scaffoldVm.Id.Guid.ToUpperInvariant()
                } |
                Select-Object -First 1

            if (-not $scaffoldSettings) {
                throw 'Unable to locate scaffold VM configuration settings.'
            }

            $scaffoldConfigPath = [System.IO.Path]::GetFullPath(
                [System.IO.Path]::Combine($scaffoldSettings.ConfigurationDataRoot, $scaffoldSettings.ConfigurationFile)
            )
            $scaffoldGuid = [guid]$scaffoldVm.Id.Guid

            Copy-Item -LiteralPath $scaffoldRoot -Destination $patchedRoot -Recurse -Force

            if ($PSCmdlet.ShouldProcess($temporaryVmName, 'Remove temporary scaffold VM registration')) {
                Remove-VM -VM $scaffoldVm -Force -ErrorAction Stop
            }

            $patchedScaffoldRoot = Join-Path -Path $patchedRoot -ChildPath (Split-Path -Path $scaffoldRoot -Leaf)
            Rename-VMRecoveryArtifacts -RootPath $patchedScaffoldRoot -OldGuid $scaffoldGuid -NewGuid $originalVmId -OldName $temporaryVmName -NewName $originalVmName

            $patchedConfigPath = Get-ChildItem -LiteralPath $patchedScaffoldRoot -Recurse -Filter ($originalVmId.Guid.ToUpperInvariant() + '.vmcx') |
                Select-Object -First 1 -ExpandProperty FullName

            if (-not $patchedConfigPath) {
                throw 'Unable to locate patched .vmcx file.'
            }

            $targetConfigDirectory = Split-Path -Path $expectedConfigurationPath -Parent
            New-Item -ItemType Directory -Path $targetConfigDirectory -Force | Out-Null

            try {
                Get-VM -Id $originalVmId -ErrorAction Stop | Remove-VM -Force -ErrorAction Stop
            } catch {
                $brokenVmRecord = Get-CimInstance -Namespace root\virtualization\v2 -ClassName MSVM_ComputerSystem |
                    Where-Object Caption -eq 'Virtual Machine' |
                    Where-Object { $_.Name.ToUpperInvariant() -eq $originalVmId.Guid.ToUpperInvariant() } |
                    Select-Object -First 1
                Remove-CimInstance -InputObject $brokenVmRecord -ErrorAction Stop
            }

            if (Test-Path -LiteralPath $expectedConfigurationPath) {
                Remove-Item -LiteralPath $expectedConfigurationPath -Force
            }

            Copy-Item -LiteralPath $patchedConfigPath -Destination $expectedConfigurationPath -Force

            Get-ChildItem -LiteralPath (Split-Path -Path $patchedConfigPath -Parent) -Filter ($originalVmId.Guid.ToUpperInvariant() + '.*') |
                Where-Object FullName -ne $patchedConfigPath |
                ForEach-Object {
                    Copy-Item -LiteralPath $_.FullName -Destination (Join-Path -Path $targetConfigDirectory -ChildPath $_.Name) -Force
                }

            Import-VM -Path $expectedConfigurationPath -Register -ErrorAction Stop | Out-Null

            $summary.Registered = $true
            $summary
        }
        catch {
            throw
        }
    }
}
