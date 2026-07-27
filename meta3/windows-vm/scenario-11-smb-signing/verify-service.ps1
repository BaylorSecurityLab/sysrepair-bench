# meta3/windows-vm/scenario-11-smb-signing/verify-service.ps1
# Regression gate. PASS (exit 0) iff LanmanServer is Running, SMB2 still on, and
# TCP/445 actually LISTENING — i.e. signing was made required WITHOUT breaking
# file sharing. Live-listener check is enforceable on a real VM.

$ErrorActionPreference = 'Stop'

try {
    $svc = Get-Service -Name LanmanServer -ErrorAction Stop
    if ($svc.Status -ne 'Running') {
        Write-Error "[verify-service-11] LanmanServer not Running (status=$($svc.Status)) — SMB broken"
        exit 1
    }

    $cfg = Get-SmbServerConfiguration
    if (-not $cfg.EnableSMB2Protocol) {
        Write-Error "[verify-service-11] SMB2 disabled — remediation broke file sharing"
        exit 1
    }

    $listen = Get-NetTCPConnection -LocalPort 445 -State Listen -ErrorAction SilentlyContinue
    if (-not $listen) {
        Write-Error "[verify-service-11] TCP/445 is not listening — SMB service not serving"
        exit 1
    }

    Write-Host "[verify-service-11] LanmanServer running, SMB2 on, 445 listening — service HEALTHY"
    exit 0
}
catch {
    Write-Error "[verify-service-11] unexpected: $_"
    exit 1
}
