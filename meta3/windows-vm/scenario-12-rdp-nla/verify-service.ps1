# meta3/windows-vm/scenario-12-rdp-nla/verify-service.ps1
# Regression gate. PASS (exit 0) iff RDP is genuinely still serving: TermService
# Running, fDenyTSConnections=0, and TCP/3389 actually LISTENING — i.e. NLA was
# enforced WITHOUT disabling RDP entirely. Live-listener check enforceable on a real VM.

$ErrorActionPreference = 'Stop'
$tsBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'

try {
    $svc = Get-Service -Name TermService -ErrorAction Stop
    if ($svc.Status -ne 'Running') {
        Write-Error "[verify-service-12] TermService not Running (status=$($svc.Status)) — RDP broken"
        exit 1
    }

    $deny = (Get-ItemProperty -Path $tsBase -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections
    if ($deny -ne 0) {
        Write-Error "[verify-service-12] RDP disabled entirely (fDenyTSConnections=$deny)"
        exit 1
    }

    $listen = Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue
    if (-not $listen) {
        Write-Error "[verify-service-12] TCP/3389 is not listening — RDP not serving"
        exit 1
    }

    Write-Host "[verify-service-12] TermService running, RDP enabled, 3389 listening — service HEALTHY"
    exit 0
}
catch {
    Write-Error "[verify-service-12] unexpected: $_"
    exit 1
}
