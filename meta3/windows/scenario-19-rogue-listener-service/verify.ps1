# Verification script for Scenario 19: rogue bind-shell service on 4444/TCP
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

$svcName  = 'WinTelemetrySvc'
$payload  = 'C:\ProgramData\WinTelemetry'
$fwRule   = 'WinTelemetry-4444'

###############################################################################
# PoC Check 1: the service must be gone
###############################################################################
$svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "FAIL [PoC]: service $svcName still registered (status=$($svc.Status))."
    exit 1
}
Write-Host "PASS [PoC]: service $svcName deleted."

###############################################################################
# PoC Check 2: the payload directory must be gone
###############################################################################
if (Test-Path $payload) {
    Write-Host "FAIL [PoC]: payload directory $payload still present."
    exit 1
}
Write-Host "PASS [PoC]: payload directory removed."

###############################################################################
# PoC Check 3: the inbound firewall rule must be gone
###############################################################################
$rule = Get-NetFirewallRule -DisplayName $fwRule -ErrorAction SilentlyContinue
if ($rule) {
    Write-Host "FAIL [PoC]: firewall rule '$fwRule' still present."
    exit 1
}
Write-Host "PASS [PoC]: firewall rule removed."

###############################################################################
# PoC Check 4: nothing is listening on 4444/TCP
###############################################################################
$listening = Get-NetTCPConnection -LocalPort 4444 -State Listen -ErrorAction SilentlyContinue
if ($listening) {
    $pids = ($listening.OwningProcess | Sort-Object -Unique) -join ','
    Write-Host "FAIL [PoC]: something is still listening on 4444/TCP (pid=$pids)."
    exit 1
}
Write-Host "PASS [PoC]: nothing listening on 4444/TCP."

###############################################################################
# PoC Check 5: no other services hide a PowerShell -File/-enc payload under
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
