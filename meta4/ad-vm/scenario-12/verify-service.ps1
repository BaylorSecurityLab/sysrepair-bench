# meta4/ad-vm/scenario-12/verify-service.ps1
# PASS (exit 0) iff a signed LDAP bind to the DC still works.

$ErrorActionPreference = 'Stop'
try {
    $u = Get-ADUser -Identity Administrator -Server corp-dc01 -ErrorAction Stop
    if ($u.SamAccountName -ne 'Administrator') {
        throw "Unexpected LDAP bind result: $($u.SamAccountName)"
    }
    Write-Host "[verify-service-12] signed LDAP bind to corp-dc01 OK -- service HEALTHY"
    exit 0
}
catch {
    Write-Error "[verify-service-12] $_"; exit 1
}
