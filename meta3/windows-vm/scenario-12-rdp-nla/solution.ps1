# meta3/windows-vm/scenario-12-rdp-nla/solution.ps1
# REFERENCE remediation (proves solvability). Run INSIDE the VM. Re-enables
# Network Level Authentication so the live listener answers a Standard-RDP-only
# X.224 Connection Request with RDP_NEG_FAILURE / HYBRID_REQUIRED_BY_SERVER
# instead of granting PROTOCOL_RDP.
#
# No Restart-Service TermService here, for the reason documented at length in
# inject.ps1: on META3WIN `Restart-Service -Name TermService -Force` fails
# outright on a freshly restored VM ("stop failed", StopServiceFailed), which
# under $ErrorActionPreference = 'Stop' killed this script on its last line --
# so the reference solution could report failure while having already applied
# the fix. It is also unnecessary: the RDP-Tcp security policy is read per
# connection, MEASURED across three transitions with no restart between them.
$ErrorActionPreference = 'Stop'

$rdpTcp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'

# Require NLA/CredSSP and force TLS at the security layer.
Set-ItemProperty -Path $rdpTcp -Name 'UserAuthentication' -Value 1 -Type DWord
Set-ItemProperty -Path $rdpTcp -Name 'SecurityLayer'      -Value 2 -Type DWord

# The fix must harden RDP, not remove it: leave the listener serving.
if ((Get-Service -Name TermService).Status -ne 'Running') { Start-Service -Name TermService }

# Prove the remediation is live rather than merely written down.
$probe = Join-Path $PSScriptRoot 'rdp_nla_probe.ps1'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $probe -TargetHost 127.0.0.1 -Port 3389
$rc = $LASTEXITCODE
if ($rc -ne 2) {
    throw "[solution-12] the live listener still does not require TLS/CredSSP (probe rc=$rc)"
}

Write-Host "[solution-12] NLA required (UserAuthentication=1, SecurityLayer=2); plain RDP refused on the wire"
