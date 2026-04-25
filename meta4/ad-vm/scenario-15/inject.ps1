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
$adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
    $_.InterfaceDescription -match 'Adapter 2' -or $_.Name -match 'hostonly|10\.20\.30'
}
foreach ($a in $adapters) {
    $tcpipKey = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$($a.InterfaceGuid)"
    if (Test-Path $tcpipKey) {
        Set-ItemProperty -Path $tcpipKey -Name 'NetbiosOptions' -Value 1 -Type DWord
    }
}

Write-Host "[inject-15] LLMNR + NBT-NS re-enabled on DC private_network NIC"
