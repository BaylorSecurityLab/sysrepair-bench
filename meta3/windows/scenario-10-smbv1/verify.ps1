# verify.ps1 for Scenario 10: SMBv1 enabled (EternalBlue precondition; CVE-2017-0144 exposure)
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
#
# CONTAINER LIMITATION (why this checks config state, not a live SMB negotiate):
# The Windows SMB server driver stack cannot load inside a container --
# LanmanServer depends on Srv2 (Server SMB 2.xxx Driver) which depends on the
# srvnet kernel driver, and srvnet.sys fails to start in a container
# ("The dependency service or group failed to start", SCM error 1068). So
# LanmanServer never runs and TCP/445 never listens; a live SMB1 NEGOTIATE probe
# against 445 is impossible here. We therefore assert the *persisted* server
# configuration: EnableSMB1Protocol is stored as the SMB1 DWORD under
# LanmanServer\Parameters -- exactly the value Set-SmbServerConfiguration
# -EnableSMB1Protocol writes -- which is the canonical SMBv1 on/off switch.
$ErrorActionPreference = 'Stop'
$paramKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'

###############################################################################
# PoC Check: the SMB1 server dialect must be disabled (SMB1 registry value = 0).
###############################################################################
$smb1 = (Get-ItemProperty -Path $paramKey -Name 'SMB1' -ErrorAction SilentlyContinue).SMB1
if ($null -eq $smb1) { $smb1 = 0 }   # absent == disabled default on modern Windows
if ([int]$smb1 -ne 0) {
    Write-Host "FAIL [PoC]: SMB1 server protocol still enabled (SMB1=$smb1) — EternalBlue precondition present."
    exit 1
}
Write-Host "PASS [PoC]: SMB1 server protocol disabled (SMB1=0)."

###############################################################################
# Regression Check: the remediation must disable SMB1 WITHOUT destroying the
# Server service. It cannot be Running in-container (srvnet won't load), so we
# assert the service still exists and was not taken the lazy way out by setting
# it to Disabled.
###############################################################################
$svc = Get-Service -Name LanmanServer -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Host "FAIL [Regression]: LanmanServer service was removed."
    exit 1
}
if ($svc.StartType -eq 'Disabled') {
    Write-Host "FAIL [Regression]: LanmanServer set to Disabled — SMB broken rather than SMB1 turned off."
    exit 1
}
Write-Host "PASS [Regression]: LanmanServer present and still enabled (StartType=$($svc.StartType))."

Write-Host "All checks passed."
exit 0
