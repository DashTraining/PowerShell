#
#        _| _ __|_           Script:  '1.03 HTML Reports.ps1'
#       (_|(_|_)| ) .        Author:  Paul 'Dash'
#      t r a i n i n g       Contact: paul@dash.training
#


# Simple HTML report examples
# Shows four complexity levels of HTML generation using ConvertTo-Html and inline styling.

# Edit this for your environment
$ReportLocation = 'T:\'



# Ensure the output folder exists
if (-not (Test-Path -Path $ReportLocation)) {
    Write-Error "Output location '$ReportLocation' does not exist. Please create it or change the path."
    exit
} else {
    $ReportPath = Join-Path $ReportLocation 'report.html'
}


# Inline CSS for styling the report
$style = @'
<style>
    body { font-family: sans-serif; margin: 1rem; }
    h1, h2 { color: #2f5496; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 1rem; }
    th, td { border: 1px solid #ccc; padding: 0.5rem; }
    th { background: #f2f2f2; }
    .stopped { background-color: #fee2e2; color: #7f1d1d; }
</style>
'@



# 1: Basic HTML report with one table and inline styling.

# Retrieve services, pick properties
$ServiceList = Get-Service -Name w32time, bits, lanmanserver, trustedinstaller |
               Select-Object DisplayName, Status, StartType
# Convert the list to HTML
$ServiceHtml = $ServiceList | ConvertTo-Html -Head  $style `
                                             -Title 'Basic Service Report' `
                                             -PreContent '<h2>Critical Services</h2>'
# Output the HTML to a file
$ServiceHtml | Out-File -FilePath $report1Path -Encoding UTF8



# 2: Report with a renamed column and color-coded rows for service status.

# Helper function to add CSS class based on service status
function Add-RowClass {
    param([string]$HtmlLine)

    if ($HtmlLine -like '*<td>Stopped</td>*') {
        return $HtmlLine.Replace('<tr>', '<tr class="stopped">')
    } else {
        return $HtmlLine
    }
}

# Retrieve services, pick properties and rename DisplayName to Service
$ServiceList = Get-Service -Name w32time, bits, lanmanserver, trustedinstaller |
               Select-Object @{Name='Service'; Expression={$_.DisplayName}}, Status, StartType

# Convert the list to HTML, as above
$ServiceHtml = $ServiceList | ConvertTo-Html -Head  $style `
                                             -Title 'Color-coded Service Report' `
                                             -PreContent '<h2>Critical Services</h2>'
# Add CSS classes to rows based on service status
$ServiceHtml = $ServiceHtml | ForEach-Object { Add-RowClass -HtmlLine $_ }
# Output to a file
$ServiceHtml | Out-File -FilePath $ReportPath -Encoding UTF8



# 3: Multi-section report with critical processes as a separate table.

# Retrieve critical processes
$ProcessList = Get-Process Win* |
               Select-Object @{Name='Process Name';Expression={$_.Name}}, Id, CPU

# Convert to HTML fragment
$ServiceFragment = $ServiceList |
                   ConvertTo-Html -Fragment -PreContent '<h2>Critical Services</h2>' |
                   ForEach-Object { Add-RowClass -HtmlLine $_ }
# Convert to HTML fragment
$ProcessFragment = $ProcessList |
                   ConvertTo-Html -Fragment -PreContent '<h2>Critical Processes</h2>'

# Combine fragments into a full HTML document
$ReportHtml = ConvertTo-Html -Head  $style `
                             -Title 'Service and Process Report' `
                             -Body  ('<h1>Service and Process Report</h1>' +
                                     $ServiceFragment +
                                     $ProcessFragment )
# Output to a file
$ReportHtml | Set-Content -Path $ReportPath -Encoding UTF8



# 4: Multi-section report templated using a helper function

# Helper function that creates HTML fragment based on input
function New-HTMLFragment {
    param(
        [Parameter(Mandatory)] [object[]]$Data,
        [Parameter(Mandatory)] [string]$Title,
        [switch]$ApplyRowClass
    )

    $fragment = $Data | ConvertTo-Html -Fragment -PreContent "<h2>$Title</h2>"

    if ($ApplyRowClass.IsPresent) {
        $fragment = $fragment | ForEach-Object { Add-RowClass -HtmlLine $_ }
    }

    return $fragment
}

# Create HTML fragments using a function, which simplifies the main logic
$ServiceFragment = New-HTMLFragment -Data $ServiceList -Title 'Critical Services' -ApplyRowClass
$ProcessFragment = New-HTMLFragment -Data $ProcessList -Title 'Critical Processes'

# Combine fragments into a full HTML document, as before
$ReportHtml = ConvertTo-Html -Head $style `
                             -Title 'Templated Service and Process Report' `
                             -Body ('<h1>Service and Process Report</h1>' +
                                    $ServiceFragment +
                                    $ProcessFragment )
# Output to a file
$ReportHtml | Set-Content -Path $ReportPath -Encoding UTF8



# 5: Using PSWriteHTML module for simplified generation of advanced HTML

# Only run this example if PSWriteHTML is installed
try {
    Import-Module PSWriteHTML -ErrorAction Stop
} catch {
    Write-Error 'PSWriteHTML module not found. Install it with: Install-Module PSWriteHTML -Scope CurrentUser'
    exit
}

# Everything is wrapped in one New-HTML command
New-HTML -TitleText 'Service Report via PSWriteHTML' {

    # HTML header and heading
    New-HTMLHeader {
        New-HTMLHeading -Heading h1 -HeadingText 'Service and Process Report' }

    # Service table with conditional row styling
    New-HTMLSection -HeaderText "Critical Services" -CanCollapse {
        New-HTMLTable -DataTable $ServiceList -PagingStyle full -SearchPane {
                New-HTMLTableCondition -Name 'Status' -Value 'Stopped' -BackgroundColor '#fee2e2' } }

    # Process table
    New-HTMLSection -HeaderText "Critical Processes" -CanCollapse {
        New-HTMLTable -DataTable $ProcessList -PagingStyle simple -SearchPane }
} -FilePath $ReportPath
