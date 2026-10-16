#
#        _| _ __|_           Script:  '2.02 WebRequest and RestMethod.ps1'
#       (_|(_|_)| ) .        Author:  Paul 'Dash'
#      t r a i n i n g       Contact: paul@dash.training
#                            Created: 2016-03-23
#                            Mod on:  2020-02-11 : new yr.no API
#


#################################################
# HTML
# Getting a simple web page
Invoke-WebRequest -Uri 'https://www.glasspaper.no' -Verbose



#################################################
# XML
# Getting the weather data

$PostalCode = '5961' # 2061 Gardermoen

# TODO: update from the old APIs
# http://om.yr.no/verdata/xml/
$yrURI = "http://www.yr.no/sted/Norge/postnummer/$PostalCode/varsel.xml"

$yrnoData = Invoke-WebRequest $yrURI

# Save the result of the web request as XML object
$WeatherResult = ([XML]$yrnoData.Content).weatherdata
# Choose forecast for the near future
$Forecast = $WeatherResult.forecast.tabular.time | Select-Object -First 1
$Forecast |
Select-Object @{N='Temp'; E={ [string]($_.temperature.value) + ' °C' }},
              @{N='Wind'; E={ if ($_.windSpeed) { ($_.windDirection.code) + ' ' + ($_.windSpeed.mps) + ' mps' }
                              else { 'no data' } }},
              @{N='Pres'; E={ $_.pressure.value }}



# Run this hidden ;)
#region Extremes
$ExtremeData = Invoke-RestMethod -Uri 'https://api.met.no/weatherapi/extremeswwc/1.3/'
$ExtremeData.weatherdata.product.time.lowestTemperatures.location |
Select-Object Name, @{Name='Temp';Expression={$_.lowestTemperature.value}} |
Sort-Object -Property Temp |
Select-Object -Last 1 |
ForEach-Object {Write-Host "Which is not as bad as $($_.Temp) degrees in $($_.Name)!"}
#endregion

# MET.no has now changed this API and the information there requires an account:
# https://frost.met.no/api.html#!/records/getRecords


#################################################
# JSON
# Validating the postal code

$PostalCode = '1415'

# https://developer.bring.com/api/postal-code/
$BringURI = 'https://api.bring.com/shippingguide/api/postalCode.json?clientUrl=dash.training&country=no&pnr='

# METHOD 1: get the HTML, look at the content, convert to JSON
$BringData = Invoke-WebRequest ($BringURI + $PostalCode)
$PostalCodeResult = $BringData.Content | ConvertFrom-Json

# METHOD 2: get the result of a REST API
$PostalCodeResult = Invoke-RestMethod ($BringURI + $PostalCode)

# If the result is valid, print out its city
if ($PostalCodeResult.valid) {
    Write-Host -F Black -B Gray "Postal code $PostalCode is valid for $($PostalCodeResult.result)."
}


$LocationForecastURI = 'https://api.met.no/weatherapi/locationforecast/2.0/compact?lat=59.90&lon=10.75'
$AuthHead = @{'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10136';
             }

$ForecastResult = Invoke-RestMethod -Headers $AuthHead -Uri $LocationForecastURI

#################################################
# Check weather at InPost parcel point

# 1. find a parcel point that supports air quality monitoring
# 2. use Edge DevTools to inspect network requests and find ID and name
# 3. make a POST request to the air_index_level endpoint

$InPostWeather = Invoke-RestMethod -Uri https://inpost.pl/shipx-point-data/41011/KRA305M/air_index_level -Headers @{"X-Requested-With"='XMLHttpRequest'} -Method Post
$InPostWeather.air_sensors

# 4. strings include label : value : percentage
