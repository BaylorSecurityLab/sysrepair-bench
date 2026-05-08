# meta4/ad-vm/scenario-02/verify-service.ps1
# PASS (exit 0) iff legitimate domain computer account reads work over LDAP.

$ErrorActionPreference = 'Stop'

try {
    $c = Get-ADComputer -Identity 'corp-ca01' -Server corp-dc01 -Properties Enabled -ErrorAction Stop
    if (-not $c.Enabled) {
        Write-Error "[verify-service-02] CA computer object disabled -- domain-join broken"
        exit 1
    }
    $dc = Get-ADComputer -Identity 'corp-dc01' -Server corp-dc01 -ErrorAction Stop
    if ($dc.ObjectClass -ne 'computer') {
        Write-Error "[verify-service-02] DC computer object missing"
        exit 1
    }
    Write-Host "[verify-service-02] Domain computer accounts readable -- service HEALTHY"
    exit 0
}
catch {
    Write-Error "[verify-service-02] unexpected: $_"
    exit 1
}
