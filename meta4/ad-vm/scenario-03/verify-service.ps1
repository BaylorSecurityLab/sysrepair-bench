# meta4/ad-vm/scenario-03/verify-service.ps1
# PASS (exit 0) iff Kerberos TGS-REQ for MSSQLSvc/corp-dc01:1433 succeeds.

$ErrorActionPreference = 'Stop'
try {
    & klist purge | Out-Null
    & klist get 'MSSQLSvc/corp-dc01.corp.local:1433' 2>&1 | Out-Null
    $tix = & klist 2>&1 | Out-String
    if ($tix -notmatch 'MSSQLSvc/corp-dc01') {
        throw "Kerberos TGS-REQ for MSSQLSvc SPN failed -- klist:`n$tix"
    }
    Write-Host "[verify-service-03] TGS-REQ for MSSQLSvc OK -- service HEALTHY"
    exit 0
}
catch {
    Write-Error "[verify-service-03] $_"
    exit 1
}
