#
#        _| _ __|_           Script:  '2.02 COM Excel Application.ps1'
#       (_|(_|_)| ) .        Author:  Paul 'Dash'
#      t r a i n i n g       Contact: paul@dash.training
#                            Created: 2021-02-09
#


# Demonstration of using complex COM interaction.
# Runs the Excel application (must be installed) and enters some data into spreadsheet.
# TODO: Parameterize the T:\ output path and wrap Excel workbook/application COM objects in try/finally cleanup so failed or interrupted demos do not leave Excel running.
# Documentation:
# https://docs.microsoft.com/en-us/office/vba/api/overview/excel/object-model

#Requires -Modules Pscx
# Requires the Out-Clipboard cmdlet from the PowerShell Community Extensions
# https://github.com/Pscx/Pscx


# Create the Excel object. This launches the application in the background.
$XLApp = New-Object -ComObject Excel.Application
# Add a new document.
$XLWorkbook = $XLApp.Workbooks.Add()
# Choose the first worksheet (tab along the bottom).
$XLSheet = $XLWorkbook.Worksheets.Item(1)
# Enter a value into row X, column Y.
$XLSheet.Cells.Item(1,1) = "Hello, Norway!"
# Show the Excel application's window.
$XLApp.Visible = $true

#

##

### WE'RE NOT DONE YET! ###

# Graphing values

# Clear the value entered above
$XLSheet.Cells.Item(1,1).ClearContents() | Out-Null

# Grab some data about running processes
$MemoryConsumers = Get-Process |
                   Select-Object -Property ProcessName,WS |
                   Sort-Object WS -Descending |
                   Select-Object -First 5
#Copy to clipboard
if (Get-Module -ListAvailable pscx) {
    $MemoryConsumers | ConvertTo-CSV -NoTypeInformation -Delimiter "`t" | Out-Clipboard
} else {
    'Oops. You need the PSCX module to copy to the clipboard here.'
    exit
}
# Paste into Excel
$XLSheet.Range("A1").Select() | Out-Null
$XLSheet.Paste()

# Define chart
$Chart = $XLSheet.Shapes.AddChart().Chart
$ChartData = $XLSheet.Range("A1:A6,B1:B6")
$Chart.SetSourceData($ChartData)

# Make chart look pretty
$Chart.ChartTitle.Text = "Top Memory Consumers"
$Chart.HasLegend = $false
$Chart.ChartType = [Microsoft.Office.Interop.Excel.XLChartType]-4100

# Save the chart as a file
$Chart.Export('T:\MemChart.jpg')
