#           _          _
#        __| |____ ___| |__
#       / _  |__  / __| '_ \           Script: '1.07 Scope.ps1'
#      | (_| |(_| \__ \ | | |          Author: Paul 'Dash'
#       \__,_\__,_|___/_| |_(_)        E-mail: paul@dash.training
#       T  R  A  I  N  I  N  G

<# Demonstration of SCOPE:
- global scope
- script scope
- function scope
- scriptblock scope
#>

# This demo expects a variable to already exist in the global scope.
if (-not (Get-Variable -Name GreetingText -Scope Global -ErrorAction SilentlyContinue)) {
    Write-Warning 'This demo expects $Greeting already exists. Set it and rerun the script.'
    Write-Host    'Also, consider stepping through the script in debug mode.' -f DarkGray
    return
}


# 1. GLOBAL, SCRIPT, FUNCTION

function Show-Greeting {
    # Before defining inside the function.
    Write-Host "In the function, Greeting is:        $Greeting" -f Black -b Cyan

    # Variable assignment
    $Greeting = 'Something different'

    # After defining in the function
    Write-Host "In the function, Greeting is now:    $Greeting" -f Black -b Cyan
}

# Before defining inside the script
Write-Host "In the script, Greeting is:          $Greeting" -f Black -b Cyan

# Variable assignment
$Greeting = 'Something'

# After defining in the script
Write-Host "In the script, Greeting is now:      $Greeting" -f Black -b Cyan

# Call function
Show-Greeting

# After calling the function
Write-Host "Back in the script, Greeting is now: $Greeting" -f Black -b Cyan


# 2. SCRIPT BLOCK

# Similarly, Scope also matters inside scriptblocks
& {
    # Before defining in the script block
    Write-Host "In the script block, Greeting is:    $Greeting" -f Black -b Cyan

    # Variable assignment
    $Greeting = 'Something completely different'

    # After defining in the script block
    Write-Host "In the script block, it is now:      $Greeting" -f Black -b Cyan
}

# After calling the script block
Write-Host "Again back in the script, it is:     $Greeting" -f Black -b Cyan


# 3. OVERRIDING SCOPE

function Set-Greeting {
    # Variable assignment
    $Greeting = 'Something on the level of the function'

    # This assignment targets the script scope, which the rest of the script will see
    Set-Variable -Name Greeting -Scope Script -Value 'Greetings from the function'

    # We can even read it, here using a simpler syntax
    Write-Host "From the function we can read it as: $script:Greeting" -f Black -b Cyan
}

# Call second function
Set-Greeting

Write-Host "Finally back in the script, it is:   $Greeting" -f Black -b Cyan


# 4. REMOTING SCOPE

# Get computer name and perform connectivity test. May still not work looping back onto localhost!
$Computer = Read-Host -Prompt 'Enter remote computer to connect to (may not work onto localhost)'
if (-not (Test-WSMan -ComputerName $Computer)) {
    Write-Warning 'PowerShell remoting is not available here, so the remoting scope demo was skipped.'
    exit
}

# Variable assignment
$Greeting = 'Hello from the caller'

# Remoting runs the scriptblock in a different session,
# so local variables do not flow there unless you pass them explicitly
Invoke-Command -ComputerName $Computer -ScriptBlock {
    Write-Host "In remote session, Greeting is:  $Greeting" -f Black -b Cyan
    Write-Host "But we can fix that by using:    $using:Greeting" -f Black -b Cyan
}

# The other way of passing the variables is to provide them like parameters
Invoke-Command -ComputerName $Computer -ArgumentList $Greeting -ScriptBlock {
    param(
        [string]$RemoteGreeting
    )
    Write-Host "In remote session, Greeting is:  $RemoteGreeting" -f Black -b Cyan
}
