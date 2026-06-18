#           _          _
#        __| |____ ___| |__
#       / _  |__  / __| '_ \           Script: '3.01 ForEach Parallel.ps1'
#      | (_| |(_| \__ \ | | |          Author: Paul 'Dash'
#       \__,_\__,_|___/_| |_(_)        E-mail: paul@dash.training
#       T  R  A  I  N  I  N  G

#Requires -Version 7

# Demo of ForEach-Object -Parallel


# 1. Simple parallel processing
$alphabet = @('A'..'Z')

# All letters are processed in parallel here
# but each waits for a different amount of time,
# so the output arrives intermixed.
$alphabet |
ForEach-Object -Parallel {
    Start-Sleep -Milliseconds (Get-Random -Minimum 50 -Maximum 250)
    Write-Host $_
} -ThrottleLimit $alphabet.Count


# 2. Comparison of helpful usage of parallel processing

# This demo calls the Rfc2898DeriveBytes class' PBKDF2 method.
# Documented here: https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rfc2898derivebytes
# PBKDF2 is a real CPU-heavy operation that derives a cryptographic key based on a password.
$password      = 'This_Is_Where_The_Password_Goes'
$iterations    = 600000 # OWASP guidelines recommend this as a secure value

$workItems     = 1..16  # this number of keys will be computed
$throttleLimit = 8      # this many in parallel

# Here work items are processed one after another.
$sequentialTime = Measure-Command {
    $workItems | ForEach-Object {
        $salt     = [byte[]](,([byte]$_) * 16)
        [System.Security.Cryptography.Rfc2898DeriveBytes]::Pbkdf2(
            [System.Text.Encoding]::UTF8.GetBytes($password),
            [byte[]]$salt,
            $iterations,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            32
        )
    }
}

# Same work, but several items can run at the same time in separate runspaces
$parallelTime = Measure-Command {
    $workItems | ForEach-Object -Parallel {
        $salt     = [byte[]](,([byte]$_) * 16)
        [System.Security.Cryptography.Rfc2898DeriveBytes]::Pbkdf2(
            [System.Text.Encoding]::UTF8.GetBytes($using:password),
            [byte[]]$salt,
            $using:iterations,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            32
        )
    } -ThrottleLimit $throttleLimit
}

"Sequential time: {0:N0} ms" -f $sequentialTime.TotalMilliseconds
"Parallel time:   {0:N0} ms" -f $parallelTime.TotalMilliseconds
