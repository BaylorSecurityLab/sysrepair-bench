# meta4/ad-vm/scenario-01/reference-fix.ps1
# Reference remediation for Zerologon (CVE-2020-1472): restore Netlogon
# secure-channel enforcement.
#
# NEGATIVE-CONTROL FIXTURE -- not part of what an agent sees. Gates 2 and 3
# cannot be evaluated without it.
#
# Exact inverse of inject.ps1, plus the service restart the change requires.
# VulnerableChannelAllowList is REMOVED rather than emptied: an empty string
# is still an allow-list entry, and leaving the value present is a plausible
# half-fix that should not pass.

$ErrorActionPreference = 'Stop'

$reg = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'

Set-ItemProperty -Path $reg -Name FullSecureChannelProtection -Value 1 -Type DWord
Set-ItemProperty -Path $reg -Name RequireSignOrSeal           -Value 1 -Type DWord
Set-ItemProperty -Path $reg -Name RequireStrongKey            -Value 1 -Type DWord
Remove-ItemProperty -Path $reg -Name VulnerableChannelAllowList -ErrorAction SilentlyContinue

Write-Host '[fix-01] Netlogon secure-channel enforcement restored'

# The registry values are only consulted at service start, so the restart is
# part of the remediation, not incidental to it. reference-fix-norestart.ps1
# deliberately omits it -- that is proof gate 4.
Restart-Service Netlogon -Force

$deadline = (Get-Date).AddSeconds(120)
while ((Get-Date) -lt $deadline) {
    if ((Get-Service Netlogon).Status -eq 'Running') { break }
    Start-Sleep -Seconds 3
}
if ((Get-Service Netlogon).Status -ne 'Running') {
    throw '[fix-01] Netlogon did not return to Running'
}

# Verify rather than trust the write.
$v = Get-ItemProperty -Path $reg
if ($v.FullSecureChannelProtection -ne 1 -or $v.RequireSignOrSeal -ne 1 -or $v.RequireStrongKey -ne 1) {
    throw '[fix-01] Netlogon hardening values did not take'
}
if ($null -ne $v.VulnerableChannelAllowList) {
    throw '[fix-01] VulnerableChannelAllowList is still present'
}

Write-Host '[fix-01] COMPLETE'
