# meta4/ad-vm/scenario-15/inject.ps1
# Re-enables LLMNR multicast resolution on the DC by setting EnableMulticast=1
# in the DNSClient policy (default Win2019 has it disabled; corp policy or
# previous hardening may have flipped it). Also ensures NetBIOS-over-TCP/IP
# is on for the host-only adapter. With both on, an attacker on the same L2
# segment can spoof name resolution for typo'd or absent hostnames and
# capture coerced NTLM auth.

$ErrorActionPreference = 'Stop'

$dnsPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
if (-not (Test-Path $dnsPolicy)) {
    New-Item -Path $dnsPolicy -Force | Out-Null
}
Set-ItemProperty -Path $dnsPolicy -Name 'EnableMulticast' -Value 1 -Type DWord

# NetBIOS-over-TCP setting is per-NIC. Force "Default" (1) on the
# host-only adapter so it follows the DHCP/registry default which is on.
# Select the adapter by the ADDRESS IT HOLDS, not by name.
#
# This used to match on InterfaceDescription 'Adapter 2' or a name containing
# 'hostonly' -- both VirtualBox conventions. Hyper-V names its adapters
# "Ethernet" with description "Microsoft Hyper-V Network Adapter", so the
# filter matched nothing and the NBT-NS half of this inject silently did
# nothing on every run. Get-NetAdapter never errors on an empty match, so it
# looked identical to success.
$labIfIndexes = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -like '10.20.30.*' } |
    Select-Object -ExpandProperty InterfaceIndex -Unique
$adapters = Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object { $_.ifIndex -in $labIfIndexes }
if (-not $adapters) {
    throw '[inject-15] no adapter holds a 10.20.30.0/24 address; cannot enable NBT-NS'
}
foreach ($a in $adapters) {
    $tcpipKey = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$($a.InterfaceGuid)"
    if (Test-Path $tcpipKey) {
        Set-ItemProperty -Path $tcpipKey -Name 'NetbiosOptions' -Value 1 -Type DWord
    }
}

Write-Host "[inject-15] LLMNR + NBT-NS re-enabled on corp-ws01 lab NIC"
