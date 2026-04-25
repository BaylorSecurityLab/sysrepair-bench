$ErrorActionPreference = 'Stop'
try {
    $svc = Get-Service Spooler
    if ($svc.StartType -eq 'Disabled' -and $svc.Status -ne 'Running') {
        Write-Host "[verify-service-16] Spooler Stopped + Disabled (KB5005010 mitigation) -- intentionally OFF"
        exit 0
    }
    if ($svc.Status -ne 'Running') {
        throw "Spooler is neither Running nor explicitly Disabled (StartType=$($svc.StartType), Status=$($svc.Status))"
    }
    $null = Get-Printer -ComputerName corp-dc01 -ErrorAction Stop
    Write-Host "[verify-service-16] Spooler running + print RPC responsive -- service HEALTHY"
    exit 0
}
catch {
    Write-Error "[verify-service-16] $_"; exit 1
}
