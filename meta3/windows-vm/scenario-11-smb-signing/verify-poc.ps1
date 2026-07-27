# meta3/windows-vm/scenario-11-smb-signing/verify-poc.ps1
# LIVE PoC gate. PASS (exit 0) iff the running server REQUIRES SMB signing
# (PoC blocked / remediated). Runs the raw SMB2 NEGOTIATE probe against the
# VM's own 127.0.0.1:445 and parses the SecurityMode flag in the live response.
#
# Probe exit codes: 0 = signing optional (VULNERABLE), 2 = required (REMEDIATED),
# 1 = probe error. Gate maps: probe==2 -> pass(0); anything else -> fail(1).

$ErrorActionPreference = 'Stop'
$probe = Join-Path $PSScriptRoot 'smb_signing_probe.ps1'

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $probe -TargetHost 127.0.0.1 -Port 445
$rc = $LASTEXITCODE

if ($rc -eq 2) {
    Write-Host "[verify-poc-11] live server requires SMB signing — PoC BLOCKED"
    exit 0
} elseif ($rc -eq 0) {
    Write-Error "[verify-poc-11] live server signals signing OPTIONAL — NTLM relay downgrade still possible"
    exit 1
} else {
    Write-Error "[verify-poc-11] probe error (rc=$rc) — cannot confirm remediation"
    exit 1
}
