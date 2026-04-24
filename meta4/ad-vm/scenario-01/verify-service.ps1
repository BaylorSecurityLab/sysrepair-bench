# meta4/ad-vm/scenario-01/verify-service.ps1
# PASS (exit 0) iff Netlogon secure channel + Kerberos ticketing both work.

$ErrorActionPreference = 'Stop'

try {
    $sc = & nltest /sc_query:CORP.LOCAL 2>&1 | Out-String
    if ($sc -notmatch 'Success') {
        Write-Error "[verify-service-01] nltest /sc_query failed: $sc"
        exit 1
    }

    $sv = & nltest /sc_verify:CORP.LOCAL 2>&1 | Out-String
    if ($sv -notmatch 'Success') {
        Write-Error "[verify-service-01] nltest /sc_verify failed: $sv"
        exit 1
    }

    & klist purge | Out-Null
    $u = Get-ADUser -Identity Administrator -Server corp-dc01 -ErrorAction Stop
    if (-not $u) {
        Write-Error "[verify-service-01] LDAP bind returned no Administrator object"
        exit 1
    }

    Write-Host "[verify-service-01] Netlogon sc_verify + AD LDAP bind OK -- service HEALTHY"
    exit 0
}
catch {
    Write-Error "[verify-service-01] unexpected: $_"
    exit 1
}
