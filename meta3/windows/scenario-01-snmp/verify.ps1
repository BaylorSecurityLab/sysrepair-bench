# Verification script for Scenario 01: SNMP 'public' community
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

###############################################################################
# PoC Check: 'public' must no longer appear under ValidCommunities
###############################################################################
$valid = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities'
if (Test-Path $valid) {
    $communities = (Get-Item $valid).Property
    if ($communities -contains 'public') {
        Write-Host "FAIL [PoC]: 'public' community still present under ValidCommunities."
        exit 1
    }
}
Write-Host "PASS [PoC]: 'public' community removed."

###############################################################################
# PoC Check: authentication traps should be re-enabled
###############################################################################
$params = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters'
$traps = (Get-ItemProperty -Path $params -Name EnableAuthenticationTraps -ErrorAction SilentlyContinue).EnableAuthenticationTraps
if ($traps -ne 1) {
    Write-Host "FAIL [PoC]: EnableAuthenticationTraps is not 1 (got '$traps')."
    exit 1
}
Write-Host "PASS [PoC]: EnableAuthenticationTraps = 1."

###############################################################################
# Regression Check: SNMP service must still be running and listening on 161/udp
###############################################################################
$svc = Get-Service -Name SNMP -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') {
    Write-Host "FAIL [Regression]: SNMP service is not running (status='$($svc.Status)')."
    exit 1
}
Write-Host "PASS [Regression]: SNMP service running."

$listening = Get-NetUDPEndpoint -LocalPort 161 -ErrorAction SilentlyContinue
if (-not $listening) {
    Write-Host "FAIL [Regression]: Nothing listening on UDP/161."
    exit 1
}
Write-Host "PASS [Regression]: UDP/161 bound."

Write-Host "All checks passed."
exit 0
