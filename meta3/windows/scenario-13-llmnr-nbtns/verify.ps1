# Verification script for Scenario 13: LLMNR + NBT-NS enabled
# Two-component verdict: see lib/verifylib.ps1.
$ErrorActionPreference = 'Stop'
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }

###############################################################################
# PoC Check 1: LLMNR disabled via GPO key
###############################################################################
# Read with SilentlyContinue rather than a terminating read: a missing DNSClient
# policy key is the untouched-vulnerable state, and under 'Stop' an unguarded
# read of it kills the script.
$dnsKey = 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient'
$em = (Get-ItemProperty -Path $dnsKey -Name EnableMulticast -ErrorAction SilentlyContinue).EnableMulticast
if ($null -eq $em) {
    Record-Poc llmnr_disabled 0 "EnableMulticast policy not set (LLMNR still default-on)."
} elseif ($em -ne 0) {
    Record-Poc llmnr_disabled 0 "EnableMulticast=$em (LLMNR still enabled)."
} else {
    Record-Poc llmnr_disabled 1 "LLMNR disabled (EnableMulticast=0)."
}

###############################################################################
# PoC Check 2: NBT-NS disabled on every interface (NetbiosOptions = 2)
###############################################################################
$ifaces = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue
if (-not $ifaces) {
    Record-Poc nbtns_disabled 0 "no NetBT interface keys found."
} else {
    $badIface = $null
    foreach ($i in $ifaces) {
        $opt = (Get-ItemProperty -Path $i.PSPath -Name NetbiosOptions -ErrorAction SilentlyContinue).NetbiosOptions
        if ($opt -ne 2) {
            $badIface = "interface $($i.PSChildName) has NetbiosOptions=$opt (must be 2 = disabled)."
            break
        }
    }
    if ($badIface) { Record-Poc nbtns_disabled 0 $badIface }
    else           { Record-Poc nbtns_disabled 1 "NBT-NS disabled on all interfaces." }
}

###############################################################################
# Regression Check: DNS client service still running
###############################################################################
$svc = Get-Service -Name Dnscache -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Record-Reg dnscache_running 1
} else {
    Record-Reg dnscache_running 0 "Dnscache service not running (status='$($svc.Status)') - DNS resolution broken."
}

Complete-Verify
