#           _          _
#        __| |____ ___| |__
#       / _  |__  / __| '_ \           Script: 'MP3 Rename.ps1'
#      | (_| |(_| \__ \ | | |          Author: Paul 'Dash'
#       \__,_\__,_|___/_| |_(_)        E-mail: paul@dash.training
#       T  R  A  I  N  I  N  G

## Functions to rename MP3 files based on duplicates and metadata.

# Remove duplicate MP3 files by matching core name and file size:
#
# 1. Scans for MP3 files with names like "Song (1).mp3", "Song (2).mp3"
# 2. Groups duplicates by core name (e.g., "Song") and file size
# 3. Keeps the first file and renames it to the core name
# 4. Deletes remaining duplicates in the group
#
# Usage: Rename-MP3Duplicate [-WhatIf] [-Confirm]
function Rename-MP3Duplicate {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param()

    # Step 1: Get all .mp3 files in current directory
    dir -Filter '*.mp3' |
    # Extract the core name (part before " (") and preserve file size
    # e.g., "Song (1).mp3" → Core="Song", Length=4521200
    select Name, @{n='Core';e={$_.Name.Substring(0,$_.Name.IndexOf(' ('))}}, Length |

    # Step 2: Group files by core name AND file size
    # Same core + same size = likely duplicates
    Group-Object -Property Core,Length |
    # ignore files without duplicates
    Where-Object Count -gt 1 |
    # and for the rest
    ForEach-Object {
        $_.Group | ForEach-Object {
            # Step 3: rename to clean core name
            if (-not $renamed) {
                if ($PSCmdlet.ShouldProcess("Rename $_.Name")) {
                    # to "Song.mp3" (without the (1), (2), etc.)
                    if (Rename-Item $_.Name "$($_.Core).mp3" -PassThru) {
                        $renamed = $true
                    }
                }
            }
            # Step 4: Delete remaining files in the group as duplicates
            else {
                if ($PSCmdlet.ShouldProcess("Remove $_.Name")) {
                    Remove-Item $_.Name -Force
                }
            }
        }
        # Reset the flag for the next duplicate group
        $renamed = $false
    }
}


# Rename files based on metadata (Artist and Title) using Shell.Application COM object
function Rename-MP3FromMetadata {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param()

    # Get all .mp3 files in current directory
    dir -Filter '*.mp3' |
    ForEach-Object {
        # Use Shell.Application COM object to read metadata
        $shell = New-Object -ComObject Shell.Application
        $folder = $shell.NameSpace($_.DirectoryName)
        $file = $folder.ParseName($_.Name)

        # Extract Artist and Title metadata (indices 13 and 21)
        $artist = $folder.GetDetailsOf($file, 13)
        $title  = $folder.GetDetailsOf($file, 21)

        # If both Artist and Title are present, rename the file
        if ($artist -and $title) {
            $newName = "$artist - $title.mp3"
            if ($PSCmdlet.ShouldProcess("Rename $_.Name to $newName")) {
                Rename-Item $_.FullName -NewName $newName
            }
        }
    }
}