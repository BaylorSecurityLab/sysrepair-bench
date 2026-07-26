# meta4/ad-vm/scenario-13/reference-fix.ps1
# Reference remediation for SMB signing disabled on the DC.
#
# NEGATIVE-CONTROL FIXTURE -- not part of what an agent sees.
#
# Without RequireSecuritySignature, an SMB session can be relayed: the server
# accepts a session the attacker did not authenticate. Requiring signing is
# the documented fix and is mandatory on domain controllers.
#
# Both the registry value and the live SMB server configuration are set.
# Set-SmbServerConfiguration applies to the running service, which is why this
# scenario can be remediated without a restart -- but the registry value is
# set too so the change survives a reboot. reference-fix-norestart.ps1 writes
# ONLY the registry value, which is the config-only half.

$ErrorActionPreference = 'Stop'

$regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
Set-ItemProperty -Path $regPath -Name RequireSecuritySignature -Value 1 -Type DWord
Set-ItemProperty -Path $regPath -Name EnableSecuritySignature  -Value 1 -Type DWord

# Applies to the RUNNING service, not just the stored configuration.
Set-SmbServerConfiguration -RequireSecuritySignature $true -Confirm:$false -Force

$cfg = Get-SmbServerConfiguration
if (-not $cfg.RequireSecuritySignature) {
    throw '[fix-13] SMB server still does not require signing'
}
if ((Get-Service LanmanServer).Status -ne 'Running') {
    throw '[fix-13] LanmanServer is not running -- disabling the service is not a remediation'
}

Write-Host '[fix-13] SMB signing required on the running server and in the registry'
Write-Host '[fix-13] COMPLETE'
