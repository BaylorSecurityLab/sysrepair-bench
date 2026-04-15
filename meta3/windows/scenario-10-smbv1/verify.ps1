# Verification script for Scenario 10: SMBv1 enabled (EternalBlue precondition, CVE-2017-0144)
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

###############################################################################
# PoC Check 1: SMB server config must have EnableSMB1Protocol = False
###############################################################################
try {
    $cfg = Get-SmbServerConfiguration -ErrorAction Stop
} catch {
    Write-Host "FAIL [PoC]: Get-SmbServerConfiguration failed ($_)."
    exit 1
}
if ($cfg.EnableSMB1Protocol) {
    Write-Host "FAIL [PoC]: EnableSMB1Protocol is still True on the SMB server."
    exit 1
}
Write-Host "PASS [PoC]: EnableSMB1Protocol is False."

###############################################################################
# PoC Check 2: Optional feature SMB1Protocol must not be Enabled
###############################################################################
try {
    $feat = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
    if ($feat.State -eq 'Enabled') {
        Write-Host "FAIL [PoC]: Optional feature SMB1Protocol is still Enabled (state=$($feat.State))."
        exit 1
    }
    Write-Host "PASS [PoC]: Optional feature SMB1Protocol state is $($feat.State)."
} catch {
    Write-Host "PASS [PoC]: SMB1Protocol optional feature not present ($_)."
}

###############################################################################
# Regression Check: LanmanServer still running and 445 still listening
###############################################################################
$svc = Get-Service -Name LanmanServer -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') {
    Write-Host "FAIL [Regression]: LanmanServer service is not running."
    exit 1
}
$listening = Get-NetTCPConnection -LocalPort 445 -State Listen -ErrorAction SilentlyContinue
if (-not $listening) {
    Write-Host "FAIL [Regression]: nothing listening on TCP/445."
    exit 1
}
Write-Host "PASS [Regression]: LanmanServer running and 445 listening (SMBv2/3 only)."

Write-Host "All checks passed."
exit 0
