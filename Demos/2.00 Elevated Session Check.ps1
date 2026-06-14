#           _          _
#        __| |____ ___| |__
#       / _  |__  / __| '_ \           Script: '2.00 Elevated Session Check.ps1'
#      | (_| |(_| \__ \ | | |          Author: Paul 'Dash'
#       \__,_\__,_|___/_| |_(_)        E-mail: paul@dash.training
#       T  R  A  I  N  I  N  G

# Snippet used to check whether the PowerShell session is running in elevated mode.


[CmdletBinding()]
param()

# WindowsIdentity represents the current security context for this PowerShell session.
# WindowsPrincipal wraps that identity so we can ask role-based questions about it.
$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)

# WindowsBuiltInRole is the built-in Windows role list;
# Administrator is the one we care about here.
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Information 'Running elevated.'
} else {
    Write-Warning 'Not running elevated. Aborting privileged work.'
}
