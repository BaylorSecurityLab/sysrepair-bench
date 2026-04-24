# meta4/ad-vm/scenario-13/verify-service.ps1
# PASS (exit 0) iff LanManServer is running and SYSVOL is readable locally.

$ErrorActionPreference = 'Stop'

try {
    $svc = Get-Service -Name LanmanServer
    if ($svc.Status -ne 'Running') {
        Write-Error "[verify-service-13] LanManServer service is not Running (status=$($svc.Status))"
        exit 1
    }

    $cfg = Get-SmbServerConfiguration
    if (-not $cfg.EnableSMB2Protocol) {
        Write-Error "[verify-service-13] SMB2 disabled on server - DC service broken"
        exit 1
    }

    # Locally list SYSVOL.
    $sysvol = Get-ChildItem '\\corp-dc01\SYSVOL\corp.local' -ErrorAction Stop
    if ($sysvol.Count -lt 1) {
        Write-Error "[verify-service-13] SYSVOL empty - directory replication likely broken"
        exit 1
    }

    Write-Host "[verify-service-13] LanManServer running, SYSVOL readable - service HEALTHY"
    exit 0
}
catch {
    Write-Error "[verify-service-13] unexpected: $_"
    exit 1
}
