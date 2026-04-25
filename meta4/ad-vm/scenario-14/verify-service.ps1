# meta4/ad-vm/scenario-14/verify-service.ps1
# PASS (exit 0) iff SMB on the DC still serves SYSVOL to legit Kerberos clients.

$ErrorActionPreference = 'Stop'
try {
    $cfg = Get-SmbServerConfiguration -ErrorAction Stop
    if (-not $cfg.EnableSMB2Protocol) {
        throw "EnableSMB2Protocol false -- SMB2 disabled"
    }
    $items = Get-ChildItem '\\corp-dc01\SYSVOL\corp.local' -ErrorAction Stop
    if ($items.Count -lt 1) {
        throw "SYSVOL listing empty"
    }
    Write-Host "[verify-service-14] SMB2 enabled + SYSVOL readable -- service HEALTHY"
    exit 0
}
catch {
    Write-Error "[verify-service-14] $_"; exit 1
}
