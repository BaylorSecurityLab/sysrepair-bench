# meta3/windows-vm/scenario-12-rdp-nla/inject.ps1
# Introduces the vuln on the hardened baseline: disable Network Level
# Authentication on the RDP-Tcp listener (UserAuthentication=0, SecurityLayer=1)
# and restart TermService so a live X.224 negotiation now accepts plain RDP.
# RDP itself stays enabled (fDenyTSConnections=0).
#
# Runs INSIDE the VM (via AutomatedLab Invoke-LabCommand, or the SSH bridge).

$ErrorActionPreference = 'Stop'

$rdpTcp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$tsBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'

# NLA off, security layer down to "negotiate" (effectively plain RDP acceptable).
Set-ItemProperty -Path $rdpTcp -Name 'UserAuthentication' -Value 0 -Type DWord
Set-ItemProperty -Path $rdpTcp -Name 'SecurityLayer'      -Value 1 -Type DWord
# Keep RDP enabled so the listener stays up and 3389 keeps listening.
Set-ItemProperty -Path $tsBase -Name 'fDenyTSConnections' -Value 0 -Type DWord

# Restart the RDP service so the listener re-reads the weakened policy.
Restart-Service -Name TermService -Force

$ua = (Get-ItemProperty -Path $rdpTcp -Name 'UserAuthentication').UserAuthentication
Write-Host "[inject-12] UserAuthentication=$ua; TermService restarted — LIVE-vulnerable"
