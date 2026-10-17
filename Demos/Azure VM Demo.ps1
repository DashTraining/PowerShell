#           _          _
#        __| |____ ___| |__
#       / _  |__  / __| '_ \           Script: 'Azure VM Demo.ps1'
#      | (_| |(_| \__ \ | | |          Author: Paul 'Dash'
#       \__,_\__,_|___/_| |_(_)        E-mail: paul@dash.training
#       T  R  A  I  N  I  N  G


# TODO: Split provisioning, inspection, modification, and cleanup into independently runnable sections with prerequisite checks, current SKUs/images, estimated cost, and confirmation before billable changes.
# TODO: Remove tenant-specific networking names and ensure cleanup tracks every resource group created by both VM examples.
Install-Module Az

# Connect to Azure Tenant
Connect-AzAccount -Subscription '<YOUR SUBSCRIPTION ID HERE>'
Get-AzSubscription

# Validate connection
Get-AzContext | Select-Object Account,Name

# Create Resource Group to hold objects
Get-AzLocation | Select-Object DisplayName,Location

$Loc = 'westeurope'
$RGName = 'rg-Demo'
New-AzResourceGroup -Name $RGName -Location $Loc


# Find available SIZEs for VM
Get-AzVMSize -Location $Loc

# Find available IMAGEs for VM
Get-AzVMImagePublisher -Location $Loc |
Where-Object {$_.PublisherName -like "Microsoft*" -and $_.PublisherName -notlike "*.Azure.*"}

Get-AzVMImageOffer -Location $Loc -PublisherName 'MicrosoftWindowsServer'

Get-AzVMImageSKU   -Location $Loc -PublisherName 'MicrosoftWindowsServer' -Offer 'WindowsServer'


# The proper way to create a VM:
#region CreateTheVM
# Create networking for the VM
# (this relies on an existing 'Demo' v-net, 'FrontEnd' subnet, and 'nsg-gdc-common' Network Security Group)
$DemoVnet = Get-AzVirtualNetwork -ResourceGroupName 'rg-GDC-INFRA-Networking'
$FrontEndSubnet = $DemoVnet.Subnets | Where-Object Name -eq 'FrontEnd'
$CommonNSG = Get-AzNetworkSecurityGroup -ResourceGroupName 'rg-GDC-INFRA-Networking' -Name 'nsg-GDC-HQ-WestEurope-FrontEnd'

$VMAddress = New-AzPublicIpAddress -ResourceGroupName $RGName `
                                   -Location $Loc `
                                   -Name 'ip-Demo-Win-2' `
                                   -Sku  'Basic'  -AllocationMethod Dynamic
$VMInterface = New-AzNetworkInterface -ResourceGroupName $RGName `
                                      -Location $Loc `
                                      -Name 'nic-Demo-Win-2' `
                                      -SubnetId $FrontEndSubnet.Id `
                                      -PublicIpAddressId $VMAddress.Id `
                                      -NetworkSecurityGroupId $CommonNSG.Id

# Create a VM configuration
$VMConfig = New-AzVMConfig -VMName 'vm-Demo-Win-2' -VMSize 'Basic_A0'
$VMConfig = Set-AzVMOperatingSystem -VM $VMConfig -Windows -ComputerName 'vm-Demo-Win-2' -Credential (Get-Credential)
$VMConfig = Add-AzVMNetworkInterface -VM $VMConfig -Id $VMInterface.Id
$VMConfig = Set-AzVMSourceImage -VM $VMConfig `
                                -PublisherName 'MicrosoftWindowsServer' `
                                -Offer 'WindowsServer' `
                                -Skus '2016-Datacenter' `
                                -Version latest

# Finally... create the VM!
New-AzVM -ResourceGroupName $RGName -Location $Loc -VM $VMConfig -OutVariable vm
#endregion

# The quicker way to create a VM:
#region SimpleParameterSet
New-AzVM -ResourceGroupName  'rg-Demo-2' `
         -Location           $Loc `
         -Name               'vm-Demo-3' `
         -Size               'Basic_A0' `
         -Image              'Win2016Datacenter' `
         -Credential         (Get-Credential) `
         -VirtualNetworkName 'vnet-GDC-HQ-WestEurope' `
         -SubnetName         'FrontEnd' `
         -SecurityGroupName  'nsg-GDC-HQ-WestEurope-FrontEnd'

         #-OutVariable vm
#endregion


# The creation with an ARM Template:
#region ARM
New-AzResourceGroupDeployment -ResourceGroupName $RGName `
                              -Mode Incremental `
                              -TemplateFile .\vm-Demo2-template.json `
                              -TemplateParameterFile .\vm-Demo2-parameters.json
#endregion

# Show information about the VM
Get-AzVM
Get-AzVM | Get-Member
Get-AzVM -Status | Get-Member
Get-AzVM -Status | Select-Object Name, PowerState

# Connect to VM
Get-AzPublicIpAddress -ResourceGroupName $RGName | Select-Object IpAddress
#mstsc /v:
#ssh

# Resize VM
$vm.HardwareProfile.VmSize = "Basic_A1"
Update-AzVM -ResourceGroupName $RGName -VM $vm[0]

# Add managed disk
$vmDiskConfig = New-AzDiskConfig -Location $Loc -CreateOption Empty -DiskSizeGB 4
$vmDataDisk   = New-AzDisk -ResourceGroupName $RGName -DiskName 'Demo-Win-2_DataDisk' -Disk $vmDiskConfig
#$vm = This variable should have been populated during VM creation
Add-AzVMDataDisk -VM $vm[0] -Name 'Demo-Win-2_DataDisk' -CreateOption Attach -ManagedDiskId $vmDataDisk.Id -Lun 1
Update-AzVM -ResourceGroupName $RGName -VM $vm[0]

# Check uptime of VMs using Log Analytics
Get-AzOperationalInsightsWorkspace

$KustoQuery = @'
Heartbeat
| where TimeGenerated > ago(30d)
| summarize heartbeat_count = count() by bin(TimeGenerated, 1h), Computer
| summarize  HoursUptime = count() by Computer
'@

$UptimeQuery = Invoke-AzOperationalInsightsQuery -Query $KustoQuery `
   -WorkspaceId ((Get-AzOperationalInsightsWorkspace).CustomerId)[0]
$UptimeQuery.Results


# Clean up
Remove-AzResourceGroup -Name $RGName -Force
