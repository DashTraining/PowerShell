#
#        _| _ __|_           Script:  '2.05 Manipulating XML.ps1'
#       (_|(_|_)| ) .        Author:  Paul 'Dash'
#      t r a i n i n g       Contact: paul@dash.training
#                            Created: 2018-11-14
#

<#
XML techniques in PowerShell

1) Load XML into memory
2) Inspect document structure
3) Navigate with dot notation
4) Try XPath and discover the namespace problem
5) Fix XPath with XmlNamespaceManager
6) Read attributes and filter nodes
7) Edit existing values
8) Create and append new elements
9) Save a modified copy

Requires sample Unattend installation file, included here as '2.05 Manipulating XML'
#>

$DemoFile   = '2.05 Manipulating XML.xml'
$OutputFile = 'Demo_XML_Unattend.xml'

# Always resolve the demo XML relative to the script file
$scriptDirectory = if ($PSScriptRoot) {
    $PSScriptRoot
} else {
    Split-Path -Path $PSCommandPath -Parent
}

$samplePath = Join-Path -Path $scriptDirectory -ChildPath $DemoFile
$outPath = Join-Path -Path $scriptDirectory -ChildPath $OutputFile


### 1) Load XML into memory

# Sample PowerShell object
$SmallPSObject = [pscustomobject]@{
    Name  = 'Answer'
    Value = 42
}

# Object can be converted to XML with ConvertTo-Xml, but the result is a string
$SmallXML = $SmallPSObject | ConvertTo-Xml -As String -Depth 1
$SmallXML.GetType().FullName

# To work with XML, we need to parse the string into an [xml] document object.
[xml]$SmallXmlLObject = $SmallXML
$SmallXmlObject

# We can also parse XML directly from a file with Get-Content and the [xml] type accelerator.
[xml]$XmlObject = Get-Content -LiteralPath $samplePath -Raw


### 2) Inspect document structure

$XmlObject.GetType().FullName
$XmlObject.DocumentElement.Name
$XmlObject.DocumentElement.NamespaceURI

# The root has several <settings> children.
$XmlObject.unattend.settings.Count


### 3) Navigate with dot notation

# Dot notation is the quickest way to explore a document.
$XmlObject.unattend.settings

# Read the pass attribute from each <settings> element.
foreach ($setting in $XmlObject.unattend.settings) {
    [pscustomobject]@{
        Pass          = $setting.pass
        ComponentCount = $setting.component.Count
    }
}

# Drill into nested elements with regular property access.
$oobeShellSetup = $XmlObject.unattend.settings |
    Where-Object pass -eq 'oobeSystem' |
    Select-Object -ExpandProperty component |
    Where-Object name -eq 'Microsoft-Windows-Shell-Setup'

$oobeShellSetup.TimeZone
$oobeShellSetup.UserAccounts.LocalAccounts.LocalAccount.Name


### 4) Try XPath and discover the namespace problem

# This looks correct, but returns nothing because the document uses a default namespace.
$brokenXPathResult = $XmlObject.SelectNodes('//component')
$brokenXPathResult.Count

# Same issue here: XPath without a namespace prefix does not match namespaced elements.
$XmlObject.SelectSingleNode('/unattend/settings')


### 5) Fix XPath with XmlNamespaceManager

$nsm = [System.Xml.XmlNamespaceManager]::new($XmlObject.NameTable)
$nsm.AddNamespace('u', 'urn:schemas-microsoft-com:unattend')
$nsm.AddNamespace('wcm', 'http://schemas.microsoft.com/WMIConfig/2002/State')

# Now the same XPath works because every element in the sample XML is in the u namespace.
$components = $XmlObject.SelectNodes('//u:component', $nsm)
$components.Count

# Select only the components in the specialize pass.
$specializeComponents = $XmlObject.SelectNodes(
    "/u:unattend/u:settings[@pass='specialize']/u:component",
    $nsm
)

$specializeComponents | ForEach-Object {
    $_.Attributes['name'].Value
}

# Select-Xml is a good alternative when you want XPath against files.
$nsMap = @{
    u   = 'urn:schemas-microsoft-com:unattend'
    wcm = 'http://schemas.microsoft.com/WMIConfig/2002/State'
}

Select-Xml -Path $samplePath -XPath '//u:settings' -Namespace $nsMap |
    Select-Object -ExpandProperty Node


### 6) Read attributes and filter nodes

$localAccounts = $XmlObject.SelectNodes('//u:LocalAccount', $nsm)

foreach ($account in $localAccounts) {
    $displayName = $account.SelectSingleNode('u:DisplayName', $nsm).InnerText
    $accountName = $account.SelectSingleNode('u:Name', $nsm).InnerText
    $action = $account.Attributes.GetNamedItem(
        'action',
        'http://schemas.microsoft.com/WMIConfig/2002/State'
    ).Value

    [pscustomobject]@{
        DisplayName = $displayName
        Name        = $accountName
        Action      = $action
    }
}

# Filter by a namespaced attribute.
$addedAccounts = $XmlObject.SelectNodes("//u:LocalAccount[@wcm:action='add']", $nsm)
$addedAccounts | ForEach-Object {
    $_.SelectSingleNode('u:Name', $nsm).InnerText
}


### 7) Edit existing values

$timeZoneNode = $XmlObject.SelectSingleNode(
    "//u:component[@name='Microsoft-Windows-Shell-Setup']/u:TimeZone",
    $nsm
)

if ($timeZoneNode) {
    "Before: $($timeZoneNode.InnerText)"
    $timeZoneNode.InnerText = 'GMT Standard Time'
    "After:  $($timeZoneNode.InnerText)"
}

# Update a simple text value in another branch.
$supportHoursNode = $XmlObject.SelectSingleNode(
    "//u:OEMInformation/u:SupportHours",
    $nsm
)

if ($supportHoursNode) {
    "Original support hours: $($supportHoursNode.InnerText)"
    $supportHoursNode.InnerText = 'Mon-Fri 08:00-18:00'
    "Updated support hours:  $($supportHoursNode.InnerText)"
}


### 8) Create and append new elements

function New-UnattendElement {
    param(
        [Parameter(Mandatory)]
        [System.Xml.XmlDocument]$Document,

        [Parameter(Mandatory)]
        [string]$Name,

        [string]$InnerText
    )

    $element = $Document.CreateElement($Name, 'urn:schemas-microsoft-com:unattend')

    if ($PSBoundParameters.ContainsKey('InnerText')) {
        $element.InnerText = $InnerText
    }

    $element
}

$localAccountsNode = $XmlObject.SelectSingleNode(
    "//u:component[@name='Microsoft-Windows-Shell-Setup']/u:UserAccounts/u:LocalAccounts",
    $nsm
)

if ($localAccountsNode) {
    $newAccount = New-UnattendElement -Document $XmlObject -Name 'LocalAccount'

    $actionAttribute = $XmlObject.CreateAttribute(
        'wcm',
        'action',
        'http://schemas.microsoft.com/WMIConfig/2002/State'
    )
    $actionAttribute.Value = 'add'
    $null = $newAccount.Attributes.Append($actionAttribute)

    $null = $newAccount.AppendChild((New-UnattendElement -Document $XmlObject -Name 'Description' -InnerText 'Demo account created by the XML lesson'))
    $null = $newAccount.AppendChild((New-UnattendElement -Document $XmlObject -Name 'DisplayName' -InnerText 'Demo User'))
    $null = $newAccount.AppendChild((New-UnattendElement -Document $XmlObject -Name 'Group' -InnerText 'Users'))
    $null = $newAccount.AppendChild((New-UnattendElement -Document $XmlObject -Name 'Name' -InnerText 'DemoUser'))

    $null = $localAccountsNode.AppendChild($newAccount)
    'Added LocalAccount DemoUser'
}


### 9) Save a modified copy

$XmlObject.Save($outPath)
"Saved modified document to $(Resolve-Path -LiteralPath $outPath)"

# Quick verification that the new account exists in the saved copy.
[xml]$savedCopy = Get-Content -LiteralPath $outPath -Raw
$savedNsm = [System.Xml.XmlNamespaceManager]::new($savedCopy.NameTable)
$savedNsm.AddNamespace('u', 'urn:schemas-microsoft-com:unattend')
$savedNsm.AddNamespace('wcm', 'http://schemas.microsoft.com/WMIConfig/2002/State')

$savedCopy.SelectSingleNode("//u:LocalAccount[u:Name='DemoUser']", $savedNsm)
