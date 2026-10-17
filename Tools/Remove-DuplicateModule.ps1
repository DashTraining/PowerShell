#           _          _
#        __| |____ ___| |__
#       / _  |__  / __| '_ \           Script: 'Remove-DuplicateModule.ps1'
#      | (_| |(_| \__ \ | | |          Author: Paul 'Dash'
#       \__,_\__,_|___/_| |_(_)        E-mail: paul@dash.training
#       T  R  A  I  N  I  N  G


# Removes duplicates of modules installed using the package manager
# and leaves only the latest version.

# Run as a cleanup task after using Update-Module!
# TODO: Add SupportsShouldProcess, distinguish side-by-side copies across module paths/scopes, and report uninstall failures rather than hiding them behind verbose output.
# TODO: Provide a dry-run example with a disposable module fixture so this is safe to teach and verify.

[cmdletbinding()]
param(
    # Generates output object with Name and Version of removed module
    [switch]$OutputRemovedModule
)

Write-Progress -Activity 'Removing duplicate modules' `
               -CurrentOperation 'Getting list of installed modules' `
               -PercentComplete 0 `
               -Id 0

Write-Verbose 'Getting list of installed modules...'

$Modules = Get-Module -ListAvailable -Verbose:$false |
           Select-Object Name,Version |
           Sort-Object   Name,Version
$DuplicateModules = $Modules |
                    Group-Object Name |
                    Where-Object Count -GT 1

Write-Verbose 'Starting module removal...'

$i = 1 # counter for progress bar

foreach ($m in $DuplicateModules) {
    Write-Progress -Activity 'Removing duplicate modules' `
                   -CurrentOperation "removal of $($m.Name)" `
                   -PercentComplete ($i++/$DuplicateModules.Count*100) `
                   -Id 0

    $Versions = $m.Group | Sort-Object Version
    for ($j = 0; $j -lt $Versions.Count -1; $j++) {
        try {
            Uninstall-Module -Name $Versions[$j].Name -RequiredVersion $Versions[$j].Version -Force -ErrorAction Stop | Out-Null
            if ($OutputRemovedModule) { # otherwise stay quiet
                New-Object PSCustomObject -Property @{ 'Name'    = $Versions[$j].Name;
                                                       'Version' = $Versions[$j].Version }
            }
            Write-Verbose "Removed $($Versions[$j].Name) version $($Versions[$j].Version)."
        } catch {
            Write-Verbose "Could not remove $($Versions[$j].Name) version $($Versions[$j].Version)."
        }
    } # END for every $Version in group
    Write-Verbose "Newer version of $($Versions[-1].Name) is $($Versions[-1].Version)."
} # END foreach $DuplicateModules group

Write-Progress -Id 0 -Completed
Write-Verbose "DONE."
