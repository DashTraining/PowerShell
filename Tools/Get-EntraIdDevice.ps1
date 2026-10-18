#           _          _
#        __| |____ ___| |__
#       / _  |__  / __| '_ \           Script: 'ADMembership.ps1'
#      | (_| |(_| \__ \ | | |          Author: Paul 'Dash'
#       \__,_\__,_|___/_| |_(_)        E-mail: paul@dash.training
#       T  R  A  I  N  I  N  G

# November 2024

# Shows how "OLD" API can still be used to access device information in EntraID
# with regular user permissions, without providing any admin consent
# TODO: Add paging, API-error handling, and a small sanitized sample response so learners can understand the transformation without tenant access.

[cmdletBinding()]
param(
    # Azure AD (now Entra ID) tenant identifier.
    [string]$TenantId
)

# Install the ADAL PowerShell module if not already installed
# Uncomment the line below if you need to install the module
# Install-Module -Name AzureAD.Standard.Preview -Force

$apiVersion  = "1.6"                        # Azure AD Graph API version
$resource    = "https://graph.windows.net"  # Azure AD Graph API resource

Connect-AzAccount

$authResult = Get-AzAccessToken -TenantId $tenantId -ResourceUrl $resource -Verbose
Write-Verbose "Logged in as $($authResult.UserId)"
$accessToken = $authResult.Token

# API Request to get all devices
$graphApiUrl = "$resource/$tenantId/devices?api-version=$apiVersion"
$headers = @{
    'Authorization' = "Bearer $accessToken";
    'Content-Type'  = "application/json"
}

# Fetch all devices
Write-Verbose "Fetching devices from Azure AD Graph API..."
$response = Invoke-RestMethod -Method Get -Uri $graphApiUrl -Headers $headers

# Process and display the devices
if ($response.value) {
    Write-Verbose "Devices found:"
    foreach ($device in $response.value) {
        [PSCustomObject]@{
            Name = $device.displayName;
            DeviceID = $device.deviceId;
            OS = $device.deviceOSType;
            OSVersion = $device.deviceOSVersion;
            JoinType = $device.profileType;
            LastLogon = $device.approximateLastLogonTimestamp
        }
    }
} else {
    throw "No devices found or insufficient permissions."
}
