# verify.ps1 for Scenario 11: SMB signing not required (NTLM relay surface)
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

$probe = 'C:\verify\smb_signing_probe.ps1'

if (-not (Test-Path $probe)) {
    Write-Host "FAIL [Regression]: smb_signing_probe.ps1 missing at $probe."
    exit 1
}

###############################################################################
# PoC Check: SMB2 NEGOTIATE must show signing REQUIRED (not optional)
###############################################################################
$probeOut = & $probe 127.0.0.1 445 2>&1
$probeRc  = $LASTEXITCODE

switch ($probeRc) {
    0 {
        Write-Host "FAIL [PoC]: SMB2 signing is optional — NTLM relay downgrade still possible."
        Write-Host "            $probeOut"
        exit 1
    }
    2 {
        Write-Host "PASS [PoC]: SMB2 signing is required (RequireSecuritySignature=$true)."
    }
    default {
        Write-Host "FAIL [Regression]: probe error — $probeOut"
        exit 1
    }
}

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