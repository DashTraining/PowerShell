#
#        _| _ __|_           Script:  profile.ps1
#       (_|(_|_)| ) .        Author:  Paul 'Dash'
#      t r a i n i n g       Contact: paul@pwsh.tv
#

# Created   2011-12-17 in Hjelmeland, Norway
# Modified  2022-12-01 with new prompt function
#           2024-02-01 version check around PredictionSource
# TODO: Separate portable profile ideas from machine-specific PSDrive paths, aliases, host colors, and Windows elevation checks; guard each optional feature independently.


# Turn off command prediction
if ((Get-PSReadLineOption).PredictionSource) {
    Set-PSReadLineOption -PredictionSource None
}

# Set up function for EDIT dependant on host
function edit {
    switch -Wildcard ($host.Name) {
        "* ISE *"   { ise $args }
        Default     { code -r $args }
    }
}

# Set up function to go to parent item
function .. {
    Set-Location -Path ..
}

# Set up function to check if running elevated
function amiadmin {
    [Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains 'S-1-5-32-544'
}

# Set up variables for Special Folders
if (!(Test-Path Variable:\Desktop)) {
    $Desktop = [Environment]::GetFolderPath("Desktop")
}
if (!(Test-Path Variable:\Documents)) {
    $Documents = [Environment]::GetFolderPath("MyDocuments")
}

# Make a drive for running demos.
$null = New-PSDrive -Name 'PS'  -PSProvider FileSystem -Root "$Documents\..\Projects\Training\PowerShell"

# Switch to PS: drive for demos.
try {
    Set-Location PS:\Demo -ErrorAction Stop
} catch [System.Management.Automation.DriveNotFoundException] {
    Write-Host "PS: drive not found. Current location is documents folder!" -f Red -b White
    Set-Location $Documents
}


# Have some fun with the 'kill' command to prevent misuse
Remove-Item Alias:\kill
function kill {
    Write-Host "`n`tKILL, v. To create a vacancy without nominating a successor." -ForegroundColor Cyan
    Write-Host "`t - Ambrose Bierce in `"The Devil's Dictionary`", published 1906`n" -ForegroundColor DarkCyan
    ### Write-Warning "Try to be more professional and use Stop-Process." -WarningAction Stop
}

# Declare colors and the console prompt
# but running in the ISE we need to do coloring differently
if ($host.Name -like "*ISE*") {
    $hostBg = 'Black' # $psISE.Options.ConsolePaneBackgroundColor
    $hostFg = 'White' # $psISE.Options.ConsolePaneForegroundColor
    $PromptFirstChar = [char]0xE0B0
} else {
    $hostBg = $Host.UI.RawUI.BackgroundColor
    $hostFg = 'White' # 'DarkGray'
    $PromptFirstChar = [char]0xE0B0
}
# Change the prompt
function prompt {
    if (Test-Path Variable:/PSDebugContext) {
        Write-Host -f $hostFg -b $hostBg '[DBG] ' -NoNewline }
    $CurrentLocation = $executionContext.SessionState.Path.CurrentLocation.Path.Split('\')
    if (($CurrentLocation.Count -gt 3)){
        $PromptPath = $($CurrentLocation[0], [char]0x2026, $CurrentLocation[-2], $CurrentLocation[-1] -join ('\'))
    } else {
        $PromptPath = $($pwd.path)
    }
    Write-Host -f $hostBg -b $hostFg "$PromptFirstChar $PromptPath " -NoNewline
    Write-Host -f $hostFg -b $hostBg "$([string]($PromptFirstChar) * ($NestedPromptLevel + 1))" -NoNewline
    return " "
}

# Don't run subsequent commands if in a Visual Studio Host
if ($host.Name -like "*Visual Studio*") {
    break
}

# Set up some colors
# TODO: These should be based on current background color
$VisibleFG = 'DarkYellow'
# Do this only if running in Console and a FullLanguage session.
# See about_Language_Modes for a detailed explanation.
if (($host.Name -eq 'ConsoleHost') -and ($ExecutionContext.SessionState.LanguageMode -eq 'FullLanguage')) {
	# Make errors more legible
    $host.PrivateData.ErrorBackgroundColor = 'white'
    # Better color for strings
    switch ((Get-Module PSReadline).Version.Major) {
        1 { Set-PSReadlineOption -TokenKind String -ForegroundColor Cyan }
        2 { Set-PSReadLineOption -Colors @{String = "Cyan"; Parameter = "Gray"; Operator = "Magenta"}}
    }
    $VisibleFG = 'Yellow'
}


# Set host application window title to indicate when running elevated
$host.ui.rawui.WindowTitle = "PowerShell {0}.{1}" -f $PSVersionTable.PSVersion.ToString().Split('.')[0..1]
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = new-object System.Security.principal.windowsprincipal($CurrentUser)
if ($principal.IsInRole("Administrators")) {
    $host.ui.rawui.WindowTitle += ' [ELEVATED]'
}

Clear-Host
if ($host.Name -eq 'ConsoleHost') {
    Write-Host -ForegroundColor DarkGray @'

  :::::::-.    :::.     .::::::.   ::   .:
   ;;,   `';,  ;;`;;   ;;;`    `  ,;;   ;;,
   `[[     [[ ,[[ '[[, '[==/[[[[,,[[[,,,[[[
    $$,    $$c$$$cc$$$c  '''    $"$$$"""$$$
    888_,o8P' 88A   8U8,88L    dP 888   "88o   d8b
    MMMMP"`   YMM   ""`  "YMmMY"  MMM    YMM   YMP


'@
}
Write-Host -BackgroundColor DarkGray -ForegroundColor White ("    session launched at $(Get-Date -Format t)").PadRight((Get-Host).UI.RawUI.WindowSize.Width)
