# meta4/ad-vm/scenario-01/reference-fix-norestart.ps1
# PROOF GATE 4 FIXTURE -- the not-restarted test.
#
# Applies the correct registry hardening but deliberately does NOT restart
# Netlogon. The running service still holds its old configuration, so the host
# is still exploitable and the PoC MUST still succeed (exit 1).
#
# If the PoC passes after this, the check is reading configuration rather than
# exercising the running service -- a config-only check wearing a behavioural
# check's clothes, which is the single most common defect this methodology
# looks for.

$ErrorActionPreference = 'Stop'

$reg = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'

Set-ItemProperty -Path $reg -Name FullSecureChannelProtection -Value 1 -Type DWord
Set-ItemProperty -Path $reg -Name RequireSignOrSeal           -Value 1 -Type DWord
Set-ItemProperty -Path $reg -Name RequireStrongKey            -Value 1 -Type DWord
Remove-ItemProperty -Path $reg -Name VulnerableChannelAllowList -ErrorAction SilentlyContinue

Write-Host '[fix-01-norestart] registry hardened; Netlogon deliberately NOT restarted'
