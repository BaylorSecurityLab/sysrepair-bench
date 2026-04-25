# meta4/ad-vm/scenario-15/verify-service.ps1
# PASS (exit 0) iff legitimate DNS resolution from the DC still works.

$ErrorActionPreference = 'Stop'
try {
    $r = Resolve-DnsName -Name 'corp-ca01.corp.local' -Server '10.20.30.5' `
            -Type A -ErrorAction Stop
    if (-not ($r | Where-Object { $_.IPAddress -match '^10\.20\.30\.6' })) {
        throw "Resolve-DnsName for corp-ca01 returned no expected A record"
    }
    Write-Host "[verify-service-15] DC DNS resolves corp-ca01 -- service HEALTHY"
    exit 0
}
catch {
    Write-Error "[verify-service-15] $_"; exit 1
}
