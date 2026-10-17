#
#        _| _ __|_           Script:  '2.03 Text Menus.ps1'
#       (_|(_|_)| ) .        Author:  Paul 'Dash'
#      t r a i n i n g       Contact: paul@dash.training
#                            Created: 2021-11-08
#



# Simple text-based menu
#################################################

# TODO: Separate menu rendering from command execution, initialize/read the choice before dispatch, and return from the demo instead of exiting the learner's host.
# TODO: Add a fallback for hosts without RawUI and use deterministic sample data where live services/volumes are not the lesson objective.
# Doesn't work in ISE because of lack of implementation of ReadKey method
# so please run this in the Console Host or Terminal
if ($Host.Name.Contains('ISE')) { Exit }

# Fancy function to draw the menu
function DrawMenu {
    param([string]$Title, [string[]]$Items, [int]$Width = ($Host.UI.RawUI.BufferSize.Width))

    $F = 'Cyan'
    $Horizontal = '-' * $Width
    $Sides      = '|' + (' ' * ($Width-2)) + '|'

    Clear-Host
    Write-Host $Horizontal -F $F
    Write-Host $Sides -F $F
      Write-Host '| ' -NoNewline -F $F
      Write-Host $Title.ToUpper().PadRight($Width-3) -NoNewline
      Write-Host '|' -F $F
    Write-Host $Horizontal -F $F
    Write-Host $Sides -F $F
    foreach ($Item in ($Items -Split '\r?\n')) {
        Write-Host '| ' -NoNewline -F $F
        Write-Host $Item.PadRight($Width-3) -NoNewline
        Write-Host '|' -F $F
    }
    Write-Host $Sides -F $F
    Write-Host $Horizontal -F $F
}

# Items to include in the menu; one per line.
$MenuItems = @'
1. Service info
2. Process info
3. Volume info
Q. Quit
'@

# Main loop to keep displaying the menu
# The loop has two mechanisms for quitting. The value of $Choice can be...
#  [a] ...checked here in the While statement.
while ($Choice -ne 'Q') {

    DrawMenu -Title 'Diagnostic tools' -Items $MenuItems -Width 40
    switch ($Choice) {
        '1' { Read-Host -Prompt 'Type service name' | Get-Service  }
        '2' { Get-Process 'explorer' }
        '3' { Get-Volume | Where-Object {$_.DriveLetter} | Format-Table DriveLetter,Size,SizeRemaining }
        'Q' { Clear-Host; Exit }        #  [b] ...or here within the Switch
        default {}
    }
    # Read the user input and react immediately without displaying character on the screen
    $Choice = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown').Character
}



# A better menu system that works across different host applications
#################################################
Clear-Host

# Build the menu
$MenuItems = @()

    $a = [System.Management.Automation.Host.ChoiceDescription]::new("&Service info")
    $a.HelpMessage = "Get running services"

    $b = [System.Management.Automation.Host.ChoiceDescription]::new("&Process info")
    $b.HelpMessage = "Get running processes"

    $c = [System.Management.Automation.Host.ChoiceDescription]::new("&Volume info")
    $c.HelpMessage = "Get disk volumes"

    $q = [System.Management.Automation.Host.ChoiceDescription]::new("&Quit")

$Title       = 'Diagnostic Tools'
$Instruction = 'Select a task from the list below.'
$MenuItems   = $a,$b,$c,$q
$DefaultItem = 3

# Calling the universal PromptForChoice method
$Choice = $Host.UI.PromptForChoice($Title, $Instruction, $MenuItems, $DefaultItem)

# The rest of the logic can be implemented as in the above Foreach loop
# based on the value that is stored in $Choice
Write-Host "The output is $Choice"

