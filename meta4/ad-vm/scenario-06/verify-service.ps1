# meta4/ad-vm/scenario-06/verify-service.ps1
# PASS (exit 0) iff DRS replication actually responds (which is the
# protocol DCSync abuses; if it works for legit callers, the service is
# healthy regardless of the ACL we're guarding).

$ErrorActionPreference = 'Stop'
try {
    $r = & repadmin /showrepl /csv 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "repadmin /showrepl exit=$LASTEXITCODE output=$r" }
    if ($r -notmatch 'CN=Schema|CN=Configuration') {
        throw "repadmin output missing expected NC references"
    }
    Write-Host "[verify-service-06] DRS replication healthy -- service HEALTHY"
    exit 0
}
catch {
    Write-Error "[verify-service-06] $_"
    exit 1
}
