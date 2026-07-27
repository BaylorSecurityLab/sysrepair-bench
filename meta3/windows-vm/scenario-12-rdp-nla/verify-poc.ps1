# meta3/windows-vm/scenario-12-rdp-nla/verify-poc.ps1
# LIVE PoC gate. PASS (exit 0) iff the running RDP listener REJECTS plain RDP
# (NLA/CredSSP enforced). Runs the raw TPKT/X.224 RDP negotiation probe against
# the VM's own 127.0.0.1:3389 — the listener genuinely answers here.
#
# Probe exit codes: 0 = plain RDP accepted (VULNERABLE), 2 = rejected/upgraded
# (REMEDIATED), 1 = probe error. Gate maps: probe==2 -> pass(0); else fail(1).

$ErrorActionPreference = 'Stop'
$probe = Join-Path $PSScriptRoot 'rdp_nla_probe.ps1'

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $probe -TargetHost 127.0.0.1 -Port 3389
$rc = $LASTEXITCODE

if ($rc -eq 2) {
    Write-Host "[verify-poc-12] live listener requires TLS/CredSSP — plain RDP BLOCKED"
    exit 0
} elseif ($rc -eq 0) {
    Write-Error "[verify-poc-12] live listener accepted plain RDP — pre-auth NLA surface still exposed"
    exit 1
} else {
    Write-Error "[verify-poc-12] probe error (rc=$rc) — cannot confirm remediation"
    exit 1
}
