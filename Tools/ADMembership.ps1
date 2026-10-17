#           _          _       
#        __| |____ ___| |__    
#       / _  |__  / __| '_ \           Script: 'ADMembership.ps1'
#      | (_| |(_| \__ \ | | |          Author: Paul 'Dash'
#       \__,_\__,_|___/_| |_(_)        E-mail: paul@dash.training
#       T  R  A  I  N  I  N  G 

#Requires -Modules ActiveDirectory

# .SYNOPSIS
# Processes file with user names to produce User / Group pairs based on AD group membership.
# .NOTES
# Script for a friend.
# TODO: Add a sample input/output walkthrough or mocked AD fixture, validate Path as a file, reset per-user state before each lookup, and correct progress to report 0-100 percent.

Param (
    # Path to user list with a sAMAccountName or DistinguishedName or SID on each line.
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]
    $Path
)

# Read file in first so we know how many users to process
$Users = Get-Content -Path $Path
$Current = 0

# Loop through the user list 
foreach ($SingleUser in $Users) {

    Write-Progress -Activity 'Getting group membership' -CurrentOperation $SingleUser -PercentComplete ($Current / $Users.Count)

    try {
        # Validate user DN
        $SingleDN = (Get-ADUser -Identity $SingleUser -ErrorAction Stop).DistinguishedName
    } catch {
        Write-Warning "Couldn't find user with identity '$SingleUser'."
    }

    # Proceed if user is valid
    if ($SingleDN) {
        try {
            # Try to get group membership
            # using LDAP_MATCHING_RULE_IN_CHAIN described in
            # https://docs.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax?redirectedfrom=MSDN#operators
            $Groups = Get-ADGroup -LDAPFilter ("(member:1.2.840.113556.1.4.1941:={0})" -f $SingleDN) -ErrorAction Stop
        } catch {
            Write-Warning "Couldn't get group membership for '$SingleUser'."
        }
               
        # Loop through result to create User / Group pair for output
        foreach ($SingleGroup in $Groups) {
            New-Object -TypeName PSObject -Property @{User=$SingleUser;Group=$SingleGroup.Name}
        }

        # Cleanup before next loop iteration
        $SingleDN = $null
    }
}
