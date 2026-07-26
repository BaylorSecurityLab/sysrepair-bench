# meta4/ad-vm/scenario-17/reference-fix.ps1
# Reference remediation for PetitPotam / EFSRPC coercion (ADV210003).
#
# NEGATIVE-CONTROL FIXTURE -- not part of what an agent sees.
#
# PetitPotam abuses MS-EFSRPC to make the DC authenticate to an
# attacker-chosen host. Microsoft's documented mitigation is an RPC filter
# blocking the EFSRPC interface for unauthenticated / remote callers.
#
# The filter is applied with `netsh rpc filter`, which takes a script on
# stdin. It applies immediately to the running RPC runtime, so no service
# restart is needed and there is no gate-4 fixture here.

$ErrorActionPreference = 'Stop'

# EFSRPC interface UUIDs. c681d488... is the modern MS-EFSR interface;
# df1941c5... is the legacy one PetitPotam also accepts.
$rpcScript = @'
filter
add rule layer=um actiontype=block
add condition field=if_uuid matchtype=equal data=c681d488-d850-11d0-8c52-00c04fd90f7e
add filter
add rule layer=um actiontype=block
add condition field=if_uuid matchtype=equal data=df1941c5-fe89-4e79-bf10-463657acf44d
add filter
quit
'@

$tmp = Join-Path $env:TEMP "srb-rpcfilter-$PID.txt"
Set-Content -LiteralPath $tmp -Value $rpcScript -Encoding ascii

try {
    & netsh -f $tmp 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "[fix-17] netsh rpc filter returned $LASTEXITCODE" }
}
finally {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
}

# Verify a filter is actually present rather than trusting netsh's exit code.
$show = (& netsh rpc filter show filter 2>&1 | Out-String)
if ($show -notmatch 'c681d488|df1941c5') {
    throw '[fix-17] no EFSRPC RPC filter present after applying'
}

Write-Host '[fix-17] EFSRPC RPC filters applied (ADV210003)'
Write-Host '[fix-17] COMPLETE'
