#           _          _       
#        __| |____ ___| |__    
#       / _  |__  / __| '_ \           Script: '3.03 Module Publishing.ps1'
#      | (_| |(_| \__ \ | | |          Author: Paul 'Dash'
#       \__,_\__,_|___/_| |_(_)        E-mail: paul@dash.training
#       T  R  A  I  N  I  N  G 


# Demo code for final stages of module creation.

# To be used in advanced courses like the MOC 55039 or custom classes.
# Makes sense only in combination with my ServiceTools module.
# TODO: Replace the T:\ SMB repository and AllUsers installs with an isolated per-user/temp lab, add prerequisite checks, and provide rollback after each publishing stage.
break # STOP RUNNING



# CREATING EXTERNAL HELP

# How does Get-ChildItem hold its help content?
Set-Location (Get-Command Get-ChildItem).Module.ModuleBase
Get-Command Get-ChildItem | Select-Object -ExpandProperty HelpFile
Invoke-Item (Get-Command Get-ChildItem | select -ExpandProperty HelpFile)

# Prerequisite
Install-Module Platyps -Scope AllUsers

Set-Location (Get-Module ServiceTools -ListAvailable).ModuleBase
New-Item -Path . -ItemType Directory -Name 'HelpSource'
New-MarkdownHelp -Module ServiceTools -OutputFolder .\HelpSource -WithModulePage

code .\HelpSource\Get-ServiceStartInfo.md
code .\HelpSource\ServiceTools.md

(Get-Culture).Name
New-ExternalHelp -Path .\HelpSource -OutputPath ((Get-Culture).Name)



# ANALYZING YOUR SCRIPT
# This is a requirement for publishing into places like the PowerShell Gallery

# Prerequisite
Install-Module PSScriptAnalyzer -Scope AllUsers

Get-ScriptAnalyzerRule
Write-Host -f White -b DarkCyan "There are $((Get-ScriptAnalyzerRule).Count) rules analyzed"

Set-Location (Get-Module ServiceTools -ListAvailable).ModuleBase
Invoke-ScriptAnalyzer .\ServiceTools.psm1 -ReportSummary



# PUBLISHING TO YOUR OWN PACKAGE PROVIDER

# Create module manifest
Set-Location (Get-Module ServiceTools -ListAvailable).ModuleBase
New-ModuleManifest -Path .\ServiceTools.psd1 `
                   -Guid (New-Guid) `
                   -Author 'Paul Dash' `
                   -Description 'Tools for working with Windows system services.' `
                   -RootModule 'ServiceTools.psm1' `
                   -FunctionsToExport Get-ServiceStartInfo

Test-ModuleManifest .\ServiceTools.psd1

# Create repository and publish
$lr = 'LocalRepository'

New-Item -Path T:\ -Name $lr -ItemType Directory
New-SmbShare -Name $lr -Path "T:\$lr" -FullAccess Administrators -ReadAccess Everyone

Register-PSRepository -Name $lr -SourceLocation "\\DASH\$lr" -InstallationPolicy Trusted

# REMEMBER to remove the HelpSource directory before publishing!
Publish-Module -Path . -Repository $lr



# DONE!

### Repository Cleanup
Unregister-PSRepository -Name $lr
Remove-SmbShare -Name $lr -Force
Remove-Item "T:\$lr" -Recurse -Force
