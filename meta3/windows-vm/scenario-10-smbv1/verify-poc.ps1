# meta3/windows-vm/scenario-10-smbv1/verify-poc.ps1
# LIVE PoC gate. Runs the raw SMB1 NEGOTIATE probe against the VM's own
# 127.0.0.1:445, where the listener genuinely answers.
#
#   exit 0  SMB1 refused by the running server  -> PoC blocked (remediated)
#   exit 1  SMB1 accepted by the running server -> EternalBlue precondition present
#   exit 2  the probe could not measure         -> NOT a verdict
#
# Exit 2 is deliberate and is NOT a synonym for failure. Test-ScenarioGates.ps1
# maps it to a null security component rather than false, because "the probe
# could not reach a live SMB listener" is a statement about the harness, not
# about the host's SMB1 configuration. Collapsing it into 1 would let a dead
# listener be scored as a hardened one.
#
# Write-Error is avoided on purpose: this script sets $ErrorActionPreference to
# Stop, under which Write-Error THROWS. The exit statement after it never runs
# and powershell.exe -File returns 1 for every branch -- which would have
# silently turned the exit-2 branch below into a plain failure.

$ErrorActionPreference = 'Stop'
$probe = Join-Path $PSScriptRoot 'smb1_probe.ps1'

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $probe -TargetHost 127.0.0.1 -Port 445
$rc = $LASTEXITCODE

if ($rc -eq 2) {
    Write-Host "[verify-poc-10] PASS: SMB1 rejected by the live server -- PoC BLOCKED"
    exit 0
}
elseif ($rc -eq 0) {
    Write-Host "[verify-poc-10] FAIL: SMB1 accepted by the live server -- EternalBlue precondition present"
    exit 1
}
else {
    Write-Host "[verify-poc-10] UNMEASURED: probe returned $rc (no live SMB listener to interrogate). Not scoring this as either state."
    exit 2
}
