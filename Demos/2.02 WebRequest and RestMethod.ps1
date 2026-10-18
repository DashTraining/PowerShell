#
#        _| _ __|_           Script:  '2.02 WebRequest and RestMethod.ps1'
#       (_|(_|_)| ) .        Author:  Paul 'Dash'
#      t r a i n i n g       Contact: paul@dash.training
#                            Created: 2016-03-23
#                            Mod on:  2026-10-19 : replace retired APIs
#


#################################################
# HTML
# Getting a simple web page
$HtmlResult = Invoke-WebRequest -Uri 'https://glasspaper.no' -TimeoutSec 20 -Verbose
$HtmlResult.Content


#################################################
# JSON response
# Validating Norwegian postal codes
# documented here: https://developer.bring.com/api/postal-code/

# use 2061 for Gardermoen
$PostalCode = '1415'

# URI, including the escaped postal code
$BringURI = "https://api.bring.com/shippingguide/api/postalCode.json?clientUrl=dash.training&country=no&pnr={0}" -f [uri]::EscapeDataString($PostalCode)

# METHOD 1: get the HTML, look at the content, convert to JSON
$BringData = Invoke-WebRequest -Uri $BringURI -TimeoutSec 20
$PostalCodeResult = $BringData.Content | ConvertFrom-Json
Write-Host 'METHOD 1: Invoke-WebRequest'
$PostalCodeResult

# If the result is valid, print out its city
if ($PostalCodeResult.valid) {
    Write-Host -F Black -B Gray "Postal code $PostalCode is valid for $($PostalCodeResult.result)."
}
else {
    throw "Postal code $PostalCode was not valid."
}

# METHOD 2: get the result of a REST API
$PostalCodeResult = Invoke-RestMethod -Uri $BringURI -TimeoutSec 20
Write-Host 'METHOD 2: Invoke-RestMethod'
$PostalCodeResult

# If the result is valid, print out its city
if ($PostalCodeResult.valid) {
    Write-Host -F Black -B Gray "Postal code $PostalCode is valid for $($PostalCodeResult.result)."
}
else {
    throw "Postal code $PostalCode was not valid."
}


#################################################
# XML response
# World Bank API - Get information about a country

$CountryCode = 'NOR'

$WorldBankURI = "https://api.worldbank.org/v2/country/{0}?format=xml" -f $CountryCode
$CountryResult = Invoke-WebRequest -Uri $WorldBankURI -TimeoutSec 20
$CountryResult.Content

$xml = [xml]$CountryResult.Content
$CountryInfo = $xml.countries.country | Select-Object -First 1

[pscustomobject]@{ Name = $CountryInfo.name; Capital = $CountryInfo.capitalCity; Coordinates = '{0}, {1}' -f $CountryInfo.latitude, $CountryInfo.longitude }


#################################################
# Another API
# This time requiring a User-Agent header

# Use 59.91 for latitude and 10.75 for longitude for Oslo
$Latitude = 59.91
$Longitude = 10.75

# Weather forecast for Oslo (latitude 59.91, longitude 10.75)
$LocationForecastURI = "https://api.met.no/weatherapi/locationforecast/2.0/compact?lat={0}&lon={1}" -f $Latitude, $Longitude

$UserAgent = 'PowerShellTeachingDemo/1.0 (+https://github.com/DashTraining/PowerShell)'

$ForecastResult = Invoke-RestMethod -UserAgent $UserAgent -Uri $LocationForecastURI -TimeoutSec 20
if (-not $ForecastResult.properties.timeseries) {
    throw 'Unexpected response (the API may have changed).'
}

$now = $ForecastResult.properties.timeseries[0]
[pscustomobject]@{
    Time = $now.time
    Temp = '{0} °C' -f $now.data.instant.details.air_temperature
    Wind = '{0} m/s from {1}°' -f $now.data.instant.details.wind_speed, $now.data.instant.details.wind_from_direction
    Pres = $now.data.instant.details.air_pressure_at_sea_level
}


#################################################
# Check weather at InPost parcel point

# 1. find a parcel point that supports air quality monitoring
# 2. use Edge DevTools to inspect network requests and find ID and name
# 3. make a POST request to the air_index_level endpoint

$InPostWeather = Invoke-RestMethod -Uri https://inpost.pl/shipx-point-data/41011/KRA305M/air_index_level -Headers @{"X-Requested-With"='XMLHttpRequest'} -Method Post
$InPostWeather.air_sensors

# 4. strings include label : value : percentage
