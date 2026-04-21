# Verification script for Scenario 19: rogue bind-shell service on 4444/TCP
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

$svcName  = 'WinTelemetrySvc'
$svcDisplayName = 'Windows Telemetry Service'
$payload  = 'C:\ProgramData\WinTelemetry'
$fwRule   = 'WinTelemetry-4444'
$roguePort = 4444

###############################################################################
# Config Check 1: the service must be gone
###############################################################################
$svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "FAIL [Config]: service $svcName still registered (status=$($svc.Status))."
    exit 1
}
Write-Host "PASS [Config]: service $svcName deleted."

###############################################################################
# Config Check 2: the payload directory must be gone
###############################################################################
if (Test-Path $payload) {
    Write-Host "FAIL [Config]: payload directory $payload still present."
    exit 1
}
Write-Host "PASS [Config]: payload directory removed."

###############################################################################
# Config Check 3: the inbound firewall rule must be gone
###############################################################################
$rule = Get-NetFirewallRule -DisplayName $fwRule -ErrorAction SilentlyContinue
if ($rule) {
    Write-Host "FAIL [Config]: firewall rule '$fwRule' still present."
    exit 1
}
Write-Host "PASS [Config]: firewall rule removed."

###############################################################################
# Behavioral Check: nothing is listening on 4444/TCP and accepting connections.
# Even if the service is gone, a rogue listener may still bind the port.
# We probe by opening a TCP connection and receiving any bytes — a bind shell
# will either send a banner or hang waiting for input.
###############################################################################
$listener = $null
try {
    $tcpTest = Test-NetConnection -ComputerName localhost -Port $roguePort `
        -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    if ($tcpTest.TcpTestSucceeded) { $listener = $tcpTest }
} catch {}

if ($listener) {
    # Port is open — try to read any banner bytes to confirm it's the rogue shell
    $bannerBytes = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.Connect('localhost', $roguePort)
        $stream = $client.GetStream()
        $stream.ReadTimeout = 3000
        $buf = New-Object byte[] 256
        $bytesRead = $stream.Read($buf, 0, 256)
        if ($bytesRead -gt 0) {
            $bannerBytes = [System.Text.Encoding]::ASCII.GetString($buf, 0, $bytesRead)
        }
        $client.Close()
    } catch {}

    if ($bannerBytes) {
        Write-Host "FAIL [PoC]: Port 4444 responds with banner: $bannerBytes"
    } else {
        Write-Host "FAIL [PoC]: Port 4444 accepts connections — no banner but listener present."
    }
    exit 1
}
Write-Host "PASS [PoC]: nothing listening on 4444/TCP (probe connection refused)."

###############################################################################
# Behavioral Check: no other services hide a PowerShell -File/-enc payload under
# ProgramData or Users\Public (the common masquerade pattern).
###############################################################################
$masq = Get-CimInstance Win32_Service | Where-Object {
    $_.PathName -match 'powershell(\.exe)?\s.*-(File|enc|EncodedCommand)\b' -and
    $_.PathName -match 'ProgramData|Users\\Public'
}
if ($masq) {
    Write-Host "FAIL [PoC]: other services still invoke PowerShell against user-writable payloads:"
    $masq | ForEach-Object { Write-Host "  - $($_.Name): $($_.PathName)" }
    exit 1
}
Write-Host "PASS [PoC]: no other masqueraded PowerShell-launcher services present."

###############################################################################
# Regression Check: the Service Control Manager is healthy
###############################################################################
$scm = Get-Service -Name 'W32Time','LanmanServer' -ErrorAction SilentlyContinue
if (-not $scm) {
    Write-Host "FAIL [Regression]: core services not enumerable — SCM may be broken."
    exit 1
}
Write-Host "PASS [Regression]: SCM responsive."

Write-Host "All checks passed."
exit 0
