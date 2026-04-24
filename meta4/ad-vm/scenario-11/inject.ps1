# meta4/ad-vm/scenario-11/inject.ps1
# Installs and configures ADCS Web Enrollment with NTLM auth over HTTP --
# the ESC8 NTLM-relay attack surface. Coercing DC authentication via
# PetitPotam/PrinterBug + relaying to /certsrv/ yields a DC certificate
# the attacker can use for PKINIT-as-DC attacks.

$ErrorActionPreference = 'Stop'

if (-not (Get-WindowsFeature -Name ADCS-Web-Enrollment).Installed) {
    Install-WindowsFeature ADCS-Web-Enrollment -IncludeManagementTools | Out-Null
    Install-AdcsWebEnrollment -Force | Out-Null
}

# Enable NTLM on /certsrv vdir (default Win2019 install only allows
# Negotiate; ESC8 requires NTLM specifically because that's what the relay
# tooling can replay).
Import-Module WebAdministration
Set-WebConfigurationProperty `
    -Filter '/system.webServer/security/authentication/windowsAuthentication/providers' `
    -Location 'Default Web Site/certsrv' `
    -Name '.' -Value @{value='NTLM'} -ErrorAction SilentlyContinue
Set-WebConfigurationProperty `
    -Filter '/system.webServer/security/authentication/windowsAuthentication' `
    -Location 'Default Web Site/certsrv' `
    -Name 'Enabled' -Value $true

# Disable Extended Protection so relayed NTLM blobs aren't bound to a TLS
# channel. ESC8 requires this; HTTPS+EPA breaks the relay.
Set-WebConfigurationProperty `
    -Filter '/system.webServer/security/authentication/windowsAuthentication/extendedProtection' `
    -Location 'Default Web Site/certsrv' `
    -Name 'tokenChecking' -Value 'None'

iisreset /restart | Out-Null
Write-Host "[inject-11] /certsrv ADCS Web Enrollment installed with NTLM-over-HTTP, EPA off"
