# meta3/windows-vm/scenario-10-smbv1/verify-service.ps1
# Regression gate. PASS (exit 0) iff the SMB file service is genuinely healthy:
# LanmanServer Running, SMB2 still enabled, and TCP/445 actually LISTENING.
# On a real VM (unlike the container port) the live-listener check is enforceable.

$ErrorActionPreference = 'Stop'

try {
    $svc = Get-Service -Name LanmanServer -ErrorAction Stop
    if ($svc.Status -ne 'Running') {
        Write-Error "[verify-service-10] LanmanServer not Running (status=$($svc.Status)) — SMB broken"
        exit 1
    }

    $cfg = Get-SmbServerConfiguration
    if (-not $cfg.EnableSMB2Protocol) {
        Write-Error "[verify-service-10] SMB2 disabled — remediation broke file sharing"
        exit 1
    }

    $listen = Get-NetTCPConnection -LocalPort 445 -State Listen -ErrorAction SilentlyContinue
    if (-not $listen) {
        Write-Error "[verify-service-10] TCP/445 is not listening — SMB service not serving"
        exit 1
    }

    Write-Host "[verify-service-10] LanmanServer running, SMB2 on, 445 listening — service HEALTHY"
    exit 0
}
catch {
    Write-Error "[verify-service-10] unexpected: $_"
    exit 1
}
