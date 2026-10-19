# PowerShell by PaulDash
# Demonstration of creating a GUI with Windows Presentation Framework.
# Window contains a grid populated with a list of services, displaying name and status.

# Import the WPF assemblies
Add-Type -Assembly PresentationFramework

# Find and load the XAML file.
$XAMLFile="$(Split-Path $MyInvocation.MyCommand.Source)\2.03 WPF with data binding.xaml"

# Parse and load the XAML using a .NET Class.
$GridWindow = [Windows.Markup.XamlReader]::Load(
   [System.Xml.XmlNodeReader]::new(
      [xml](Get-Content -Path $XAMLFile -Raw)
   )
)

# Retrieve dataset for the grid.
$services = Get-Service | Select-Object Name, Status

# The XAML binds ItemsSource to the dynamic resource named 'Services'.
# Assigning the service data to that same resource name supplies the grid's rows.
$GridWindow.Resources["Services"] = $services

# Display the window.
$GridWindow.ShowDialog()
