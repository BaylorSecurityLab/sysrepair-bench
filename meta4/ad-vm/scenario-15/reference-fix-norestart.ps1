# meta4/ad-vm/scenario-15/reference-fix-norestart.ps1
#
# NEGATIVE-CONTROL FIXTURE for gate 4 (the not-restarted test).
#
# GATE 4 GENUINELY APPLIES TO THIS SCENARIO -- unlike 12, 13 and 19, where the
# remediation takes effect immediately and the fixture only documents that.
#
# This writes the CORRECT configuration and deliberately skips the policy
# refresh. EnableMulticast lives under the Policies key and the DNS Client picks
# it up via Group Policy, not per query, so the value reads as remediated while
# the host keeps answering LLMNR. Measured on the live lab: with
# EnableMulticast already 0, corp-ws01 still replied to an LLMNR query for its
# own name, and went silent only after gpupdate /force.
#
# A check that merely read the registry would pass here and be wrong. gate 4
# passes only if verify-poc.sh still reports the host POISONABLE after this
# fixture runs -- which it will, because it sends a real LLMNR query and listens
# for a real answer rather than reading a setting.
#
# Note that restarting the service is not the alternative: Dnscache is
# protected and Restart-Service fails with "Cannot open Dnscache service on
# computer '.'". gpupdate is the supported refresh, and its ABSENCE is exactly
# what this fixture is modelling.

$ErrorActionPreference = 'Stop'

# Correct configuration, applied exactly as reference-fix.ps1 does...
$dnsPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
if (-not (Test-Path $dnsPolicy)) { New-Item -Path $dnsPolicy -Force | Out-Null }
Set-ItemProperty -Path $dnsPolicy -Name 'EnableMulticast' -Value 0 -Type DWord

$ifRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
foreach ($iface in (Get-ChildItem -Path $ifRoot -ErrorAction SilentlyContinue)) {
    Set-ItemProperty -Path $iface.PSPath -Name 'NetbiosOptions' -Value 2 -Type DWord -ErrorAction SilentlyContinue
}

# ...and deliberately NO `gpupdate /force`. That omission is the whole point.

Write-Host '[fix-15-norestart] EnableMulticast=0 written; policy refresh deliberately SKIPPED'
Write-Host '[fix-15-norestart] the host should still answer LLMNR -- a config-only "fix"'
