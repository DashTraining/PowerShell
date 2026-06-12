#           _          _
#        __| |____ ___| |__
#       / _  |__  / __| '_ \           Script: '3.01 File IO.ps1'
#      | (_| |(_| \__ \ | | |          Author: Paul 'Dash'
#       \__,_\__,_|___/_| |_(_)        E-mail: paul@dash.training
#       T  R  A  I  N  I  N  G

# File and folder input/output examples, including dialogs, metadata inspection, and streaming I/O


## Basics

# File write
Set-Content -Path '.\demo-file-io.txt' -Value 'Hello world' -Encoding UTF8
Add-Content -Path '.\demo-file-io.txt' -Value 'Second line'
'Third line' | Out-File -FilePath '.\demo-file-io.txt' -Encoding UTF8

# File read
Get-Content -Path '.\demo-file-io.txt'

## Efficient

# File read as a single string
$rawText = Get-Content -Path '.\demo-file-io.txt' -Raw -Encoding UTF8
Write-Host "Raw text length: $($rawText.Length)"

# Batch processing read with ReadCount
Get-Content -Path '.\demo-file-io.txt' -ReadCount 2 | ForEach-Object {
    Write-Host 'Batch:'
    $_
}

## File write as stream with .NET
$streamFile = '.\demo-stream.txt'
$writer = [System.IO.StreamWriter]::new($streamFile, $false, [System.Text.Encoding]::UTF8)
$writer.WriteLine('Stream line 1')
$writer.WriteLine('Stream line 2')
$writer.Flush()
$writer.Close()

# File read as stream with .NET
$reader = [System.IO.StreamReader]::new($streamFile, [System.Text.Encoding]::UTF8)
while (-not $reader.EndOfStream) {
    $reader.ReadLine()
}
$reader.Close()

## Referencing paths

# Simple, but error-prone
function Open-Something {
    param( [string]$Path )
}

# Better, as it will check/convert paths automatically
# and will also work with calls like "Get-ChildItem | Open-Something"
function Open-Something {
    param( [System.IO.FileInfo]$Path )
}

# Problematic locking your own file :(
'This is a test.' | Out-File test.txt -NoClobber
Get-Content .\test.txt | Set-Content .\test.txt -Encoding utf8

## System Dialogs

# Launch directory selection dialog
# Documentation on MSDN for Shell.BrowseForFolder method
# http://msdn.microsoft.com/en-us/library/windows/desktop/bb774065(v=vs.85).aspx
try {
    $Folder = (New-Object -ComObject Shell.application).browseforFolder(0,"Select Target",0x00000201).Self.Path
}
catch {
    Write-Warning "Folder selection cancelled or failed."
    $Folder = $null
} finally {
    $Folder
}

# Launch file selection dialog
try {
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = 'Text files (*.txt)|*.txt|All files (*.*)|*.*'
    if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $File = $dialog.FileName
    } else {
        $File = $null
    }
} catch {
    Write-Warning "File selection cancelled or failed."
    $File = $null
} finally {
    $File
}
