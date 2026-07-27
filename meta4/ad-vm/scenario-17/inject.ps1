# meta4/ad-vm/scenario-17/inject.ps1
#
# Restore the pre-ADV210003 state: no RPC filter on the EFSRPC interfaces.
#
# `netsh rpc filter shutdown` DID NOT DO THIS, despite the name and despite
# exiting 0. Measured on the live DC: after reference-fix.ps1 applied the two
# EFSRPC filters, this inject ran and `netsh rpc filter show filter` still
# listed both UUIDs. The vulnerable state was never restored.
#
# It went unnoticed because gate 1 runs immediately after a baseline restore,
# where no filter exists yet, so "clear the filter" and "do nothing" look
# identical. Only gate 3 -- re-inject AFTER the fix has been applied -- can tell
# them apart, and it failed for exactly this reason.
#
# `delete filter all` inside the rpc filter context is what actually removes
# them, and the removal is verified below rather than trusted.

$ErrorActionPreference = 'Stop'

$rpcScript = @'
rpc filter
delete filter all
quit
'@

$tmp = Join-Path $env:TEMP "srb-rpcfilter-clear-$PID.txt"
Set-Content -LiteralPath $tmp -Value $rpcScript -Encoding ascii

try {
    & netsh -f $tmp 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "[inject-17] netsh delete filter all returned $LASTEXITCODE" }
}
finally {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
}

# Verify the filters are gone rather than trusting the exit code -- the whole
# reason the previous version was wrong is that it exited 0 having changed
# nothing.
$show = (& netsh rpc filter show filter 2>&1 | Out-String)
if ($show -match 'c681d488|df1941c5') {
    throw '[inject-17] EFSRPC filters still present after delete; the host is not in the vulnerable state'
}

# Remove any explicit firewall rule named PetitPotam (sometimes shipped
# by hardening templates).
Get-NetFirewallRule -DisplayName '*PetitPotam*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule

Write-Host "[inject-17] EFSRPC RPC-filters deleted and verified absent -- pre-ADV210003 state"
