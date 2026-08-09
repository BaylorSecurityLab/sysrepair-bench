# meta3/windows-vm/scenario-11-smb-signing/verify-poc.ps1
# LIVE PoC gate. Runs the raw SMB2 NEGOTIATE probe against the VM's own
# 127.0.0.1:445 and grades the SecurityMode field the live server returns.
#
#   exit 0  server REQUIRES message signing -> NTLM relay downgrade blocked
#   exit 1  server only OFFERS signing      -> relay surface present
#   exit 2  the probe could not measure     -> NOT a verdict
#
# Exit 2 is deliberate and is NOT a synonym for failure. The previous revision
# mapped "probe error" to exit 1, i.e. it reported a HARNESS failure as a
# SECURITY verdict: a dead SMB listener, a timeout, or a bug in the probe all
# scored identically to a server that genuinely advertises optional signing.
# Test-ScenarioGates.ps1 maps 2 to a null security component instead of false,
# so an unmeasurable run is visibly unmeasured rather than quietly graded.
#
# Write-Error is avoided on purpose: this script sets $ErrorActionPreference to
# Stop, under which Write-Error THROWS. The exit statement after it never runs
# and powershell.exe -File returns 1 for every branch -- which is what silently
# collapsed the exit-2 branch into a plain failure here, and what made this
# gate's stderr kill Invoke-LabCommand before the summary record was written.

$ErrorActionPreference = 'Stop'
$probe = Join-Path $PSScriptRoot 'smb_signing_probe.ps1'

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $probe -TargetHost 127.0.0.1 -Port 445
$rc = $LASTEXITCODE

if ($rc -eq 2) {
    Write-Host "[verify-poc-11] PASS: live server requires SMB signing -- relay downgrade BLOCKED"
    exit 0
}
elseif ($rc -eq 0) {
    Write-Host "[verify-poc-11] FAIL: live server signals signing OPTIONAL -- NTLM relay downgrade still possible"
    exit 1
}
else {
    Write-Host "[verify-poc-11] UNMEASURED: probe returned $rc (no SMB2 NEGOTIATE response to read SecurityMode from). Not scoring this as either state."
    exit 2
}
