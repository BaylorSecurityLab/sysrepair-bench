# meta4/ad-vm/scenario-01/inject.ps1
# Weakens Netlogon secure channel to the Zerologon-vulnerable state
# (CVE-2020-1472). Reverses the August 2020 / February 2021 enforcement
# patches by clearing FullSecureChannelProtection and the sign/seal
# requirements, so a zeroed-credential NetrServerAuthenticate3 succeeds.

$ErrorActionPreference = 'Stop'

$reg = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'

Set-ItemProperty -Path $reg -Name FullSecureChannelProtection -Value 0 -Type DWord
Set-ItemProperty -Path $reg -Name RequireSignOrSeal            -Value 0 -Type DWord
Set-ItemProperty -Path $reg -Name RequireStrongKey             -Value 0 -Type DWord
Set-ItemProperty -Path $reg -Name VulnerableChannelAllowList   -Value '*' -Type String

Restart-Service Netlogon -Force
Write-Host "[inject-01] Netlogon secure channel weakened (Zerologon-vulnerable state)"
