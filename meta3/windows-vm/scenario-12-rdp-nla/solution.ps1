# meta3/windows-vm/scenario-12-rdp-nla/solution.ps1
# REFERENCE remediation (proves solvability). Run INSIDE the VM. On a real VM
# this genuinely makes the live listener require TLS+CredSSP, so the post-fix
# X.224 negotiation rejects/upgrades plain RDP and verify-poc passes.
$ErrorActionPreference = 'Stop'

$rdpTcp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'

# Require NLA/CredSSP and force TLS at the security layer.
Set-ItemProperty -Path $rdpTcp -Name 'UserAuthentication' -Value 1 -Type DWord
Set-ItemProperty -Path $rdpTcp -Name 'SecurityLayer'      -Value 2 -Type DWord

# Restart the listener so it enforces the new policy immediately.
Restart-Service -Name TermService -Force

Write-Host "[solution-12] NLA required (UserAuthentication=1, SecurityLayer=2); TermService restarted"
