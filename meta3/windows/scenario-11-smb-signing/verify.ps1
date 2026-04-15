# Verification script for Scenario 11: SMB signing not required (NTLM relay surface)
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

###############################################################################
# PoC Check: SMB server must require signing
###############################################################################
try {
    $cfg = Get-SmbServerConfiguration -ErrorAction Stop
} catch {
    Write-Host "FAIL [PoC]: Get-SmbServerConfiguration failed ($_)."
    exit 1
}
if (-not $cfg.RequireSecuritySignature) {
    Write-Host "FAIL [PoC]: RequireSecuritySignature is False — relay downgrade still possible."
    exit 1
}
if (-not $cfg.EnableSecuritySignature) {
    Write-Host "FAIL [PoC]: EnableSecuritySignature is False."
    exit 1
}
Write-Host "PASS [PoC]: SMB server requires signing."

###############################################################################
# Regression Check: LanmanServer running, 445 listening
###############################################################################
$svc = Get-Service -Name LanmanServer -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') {
    Write-Host "FAIL [Regression]: LanmanServer is not running."
    exit 1
}
$listening = Get-NetTCPConnection -LocalPort 445 -State Listen -ErrorAction SilentlyContinue
if (-not $listening) {
    Write-Host "FAIL [Regression]: nothing listening on TCP/445."
    exit 1
}
Write-Host "PASS [Regression]: LanmanServer running and 445 listening with signing required."

Write-Host "All checks passed."
exit 0
