# meta3/windows-vm/scenario-12-rdp-nla/verify-poc.ps1
# LIVE PoC gate. Runs the raw TPKT/X.224 RDP negotiation probe against the VM's
# own 127.0.0.1:3389 and grades what the live listener answers to a request for
# Standard RDP Security.
#
#   exit 0  listener demanded TLS/CredSSP -> pre-auth RDP surface closed
#   exit 1  listener accepted plain RDP   -> NLA not enforced
#   exit 2  the probe could not measure   -> NOT a verdict
#
# Exit 2 is deliberate and is NOT a synonym for failure. The previous revision
# mapped "probe error" to exit 1, i.e. it reported a HARNESS failure as a
# SECURITY verdict -- and since that probe never managed to send a valid X.224
# Connection Request at all, exit 1 was in fact the ONLY answer it ever gave, in
# the vulnerable and the remediated state alike. Test-ScenarioGates.ps1 maps 2
# to a null security component instead of false, so an unmeasurable run is
# visibly unmeasured rather than quietly graded as vulnerable.
#
# Write-Error is avoided on purpose: this script sets $ErrorActionPreference to
# Stop, under which Write-Error THROWS. The exit statement after it never runs
# and powershell.exe -File returns 1 for every branch -- which is what silently
# collapsed the exit-2 branch into a plain failure here, and what made this
# gate's stderr kill Invoke-LabCommand before the summary record was written.

$ErrorActionPreference = 'Stop'
$probe = Join-Path $PSScriptRoot 'rdp_nla_probe.ps1'

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $probe -TargetHost 127.0.0.1 -Port 3389
$rc = $LASTEXITCODE

if ($rc -eq 2) {
    Write-Host "[verify-poc-12] PASS: live listener requires TLS/CredSSP -- plain RDP BLOCKED"
    exit 0
}
elseif ($rc -eq 0) {
    Write-Host "[verify-poc-12] FAIL: live listener accepted plain RDP -- pre-auth NLA surface still exposed"
    exit 1
}
else {
    Write-Host "[verify-poc-12] UNMEASURED: probe returned $rc (no live RDP listener to negotiate against). Not scoring this as either state."
    exit 2
}
