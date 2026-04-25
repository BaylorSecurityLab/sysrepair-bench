$ErrorActionPreference = 'Stop'
try {
    $items = Get-ChildItem '\\corp-dc01\SYSVOL\corp.local\Policies' -ErrorAction Stop
    if ($items.Count -lt 1) {
        throw "SYSVOL Policies empty -- GPO processing likely broken"
    }
    $gpos = Get-GPO -All -Domain corp.local -ErrorAction Stop
    if ($gpos.Count -lt 1) {
        throw "Get-GPO returned no policies"
    }
    Write-Host "[verify-service-18] SYSVOL readable + Get-GPO returns policies -- service HEALTHY"
    exit 0
}
catch {
    Write-Error "[verify-service-18] $_"; exit 1
}
