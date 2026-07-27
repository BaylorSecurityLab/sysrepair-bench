# meta3/windows-vm/scenario-10-smbv1/verify-poc.ps1
# LIVE PoC gate. PASS (exit 0) iff SMB1 is REJECTED by the running server
# (PoC blocked / remediated). Runs the raw SMB1 NEGOTIATE probe against the
# VM's own 127.0.0.1:445 — the listener genuinely answers here.
#
# Probe exit codes: 0 = SMB1 accepted (VULNERABLE), 2 = rejected (REMEDIATED),
# 1 = probe error. This gate maps: probe==2 -> pass(0); anything else -> fail(1).

$ErrorActionPreference = 'Stop'
$probe = Join-Path $PSScriptRoot 'smb1_probe.ps1'

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $probe -TargetHost 127.0.0.1 -Port 445
$rc = $LASTEXITCODE

if ($rc -eq 2) {
    Write-Host "[verify-poc-10] SMB1 rejected by live server — PoC BLOCKED"
    exit 0
} elseif ($rc -eq 0) {
    Write-Error "[verify-poc-10] SMB1 accepted by live server — EternalBlue precondition present"
    exit 1
} else {
    Write-Error "[verify-poc-10] probe error (rc=$rc) — cannot confirm remediation"
    exit 1
}
