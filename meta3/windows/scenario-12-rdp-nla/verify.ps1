# verify.ps1 for Scenario 12: RDP with Network Level Authentication disabled (pre-auth attack surface)
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
#
# CONTAINER LIMITATION (why this checks config state, not a live X.224 probe):
# Remote Desktop Services (TermService) cannot start inside a Windows container
# ("Cannot start service TermService on computer '.'"; it ships Stopped/Disabled),
# so TCP/3389 never listens and a live TPKT/X.224 RDP negotiation probe is
# impossible here. We therefore assert the enforced RDP-Tcp security policy that
# the listener would read per connection: NLA/CredSSP required (UserAuthentication=1)
# and TLS required at the security layer (SecurityLayer>=2).
$ErrorActionPreference = 'Stop'
$rdpTcp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$tsBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'

###############################################################################
# PoC Check: NLA (UserAuthentication=1) must be enforced, and the security layer
# must require TLS (SecurityLayer>=2) so plain-RDP negotiation is rejected.
###############################################################################
$ua = (Get-ItemProperty -Path $rdpTcp -Name 'UserAuthentication' -ErrorAction SilentlyContinue).UserAuthentication
$sl = (Get-ItemProperty -Path $rdpTcp -Name 'SecurityLayer' -ErrorAction SilentlyContinue).SecurityLayer
if ([int]$ua -ne 1) {
    Write-Host "FAIL [PoC]: NLA disabled (UserAuthentication=$ua) — pre-auth RDP surface still exposed."
    exit 1
}
if ([int]$sl -lt 2) {
    Write-Host "FAIL [PoC]: RDP security layer does not require TLS (SecurityLayer=$sl) — plain RDP still negotiable."
    exit 1
}
Write-Host "PASS [PoC]: NLA/CredSSP required (UserAuthentication=1) and TLS required (SecurityLayer=$sl)."

###############################################################################
# Regression Check: RDP must not have been "fixed" by disabling it entirely.
# (3389 cannot listen in-container because TermService can't start, so we assert
# fDenyTSConnections=0 rather than a live listener.)
###############################################################################
try {
    $deny = (Get-ItemProperty -Path $tsBase -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections
} catch {
    Write-Host "FAIL [Regression]: could not read fDenyTSConnections ($_)."
    exit 1
}
if ($deny -ne 0) {
    Write-Host "FAIL [Regression]: RDP has been disabled entirely (fDenyTSConnections=$deny)."
    exit 1
}
Write-Host "PASS [Regression]: RDP remains enabled (fDenyTSConnections=0)."

Write-Host "All checks passed."
exit 0
