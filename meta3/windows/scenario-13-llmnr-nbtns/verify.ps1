# Verification script for Scenario 13: LLMNR + NBT-NS enabled
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

###############################################################################
# PoC Check 1: LLMNR disabled via GPO key
###############################################################################
$dnsKey = 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient'
try {
    $em = (Get-ItemProperty -Path $dnsKey -Name EnableMulticast -ErrorAction Stop).EnableMulticast
} catch {
    Write-Host "FAIL [PoC]: EnableMulticast policy not set (LLMNR still default-on)."
    exit 1
}
if ($em -ne 0) {
    Write-Host "FAIL [PoC]: EnableMulticast=$em (LLMNR still enabled)."
    exit 1
}
Write-Host "PASS [PoC]: LLMNR disabled (EnableMulticast=0)."

###############################################################################
# PoC Check 2: NBT-NS disabled on every interface (NetbiosOptions = 2)
###############################################################################
$ifaces = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue
if (-not $ifaces) {
    Write-Host "FAIL [PoC]: no NetBT interface keys found."
    exit 1
}
foreach ($i in $ifaces) {
    $opt = (Get-ItemProperty -Path $i.PSPath -Name NetbiosOptions -ErrorAction SilentlyContinue).NetbiosOptions
    if ($opt -ne 2) {
        Write-Host "FAIL [PoC]: interface $($i.PSChildName) has NetbiosOptions=$opt (must be 2 = disabled)."
        exit 1
    }
}
Write-Host "PASS [PoC]: NBT-NS disabled on all interfaces."

###############################################################################
# Regression Check: DNS client service still running
###############################################################################
$svc = Get-Service -Name Dnscache -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') {
    Write-Host "FAIL [Regression]: Dnscache service not running — DNS resolution broken."
    exit 1
}
Write-Host "PASS [Regression]: DNS client service still running."

Write-Host "All checks passed."
exit 0
