#           _          _
#        __| |____ ___| |__
#       / _  |__  / __| '_ \           Script: 'Azure VPN Certificates Demo.ps1'
#      | (_| |(_| \__ \ | | |          Author: Paul 'Dash'
#       \__,_\__,_|___/_| |_(_)        E-mail: paul@dash.training
#       T  R  A  I  N  I  N  G

# TODO: Fix the "$DriveLetter:" interpolation parse error by delimiting the variable, replace ConvertTo-Base64 with a self-contained supported conversion, and parameterize the output path.
# TODO: Explain and clean up the certificates/private keys created by the lesson; do not leave exportable keys in the learner's personal store without an explicit choice.
# Creates a self-signed root certificate for signing client certificates
$cert = New-SelfSignedCertificate -Type Custom -KeySpec Signature `
                                  -Subject "CN=VPN-CA" `
                                  -KeyExportPolicy Exportable `
                                  -HashAlgorithm sha256 -KeyLength 2048 `
                                  -CertStoreLocation "Cert:\CurrentUser\My" `
                                  -KeyUsageProperty Sign -KeyUsage CertSign

# Picks drive to save temporary file
$DriveLetter =  Get-Volume |
                Where-Object DriveLetter |
                Sort-Object DriveLetter |
                Select-Object -Last 1 -ExpandProperty DriveLetter

# Displays above root certificate
# Copy-and-paste this into the 'Point-to-site configuration' page of the 'Virtual network gateway'
# in the section 'Root certificates'
$cert.rawdata | ConvertTo-Base64 -NoLineBreak | Out-File "$DriveLetter:\vpn-CA.txt"
notepad.exe "$DriveLetter:\vpn-CA.txt"

# Creates a client certificate that is placed into the current user's Private certificate store
New-SelfSignedCertificate -Type Custom -DnsName DemoVPN-Client -KeySpec Signature `
                                  -Subject "CN=VPN-Client" -KeyExportPolicy Exportable `
                                  -HashAlgorithm sha256 -KeyLength 2048 `
                                  -CertStoreLocation "Cert:\CurrentUser\My" `
                                  -Signer $cert -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2")
