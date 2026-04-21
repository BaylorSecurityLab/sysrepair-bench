# verify.ps1 for Scenario 10: SMBv1 enabled (EternalBlue precondition; CVE-2017-0144 exposure)
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

$probe = 'C:\verify\smb1_probe.ps1'

if (-not (Test-Path $probe)) {
    Write-Host "FAIL [Regression]: smb1_probe.ps1 missing at $probe."
    exit 1
}

###############################################################################
# PoC Check: SMB1 NEGOTIATE must be rejected (server must not accept SMB1 dialect)
###############################################################################
$probeOut = & $probe 127.0.0.1 445 2>&1
$probeRc  = $LASTEXITCODE

switch ($probeRc) {
    0 {
        Write-Host "FAIL [PoC]: SMB1 NEGOTIATE accepted — EternalBlue preconditions still present."
        Write-Host "            $probeOut"
        exit 1
    }
    2 {
        Write-Host "PASS [PoC]: SMB1 NEGOTIATE rejected (EnableSMB1Protocol=$false)."
    }
    default {
        Write-Host "FAIL [Regression]: probe error — $probeOut"
        exit 1
    }
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