# Verification script for Scenario 12: RDP NLA disabled
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

$rdpKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$tsKey  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'

###############################################################################
# PoC Check: NLA must be on (UserAuthentication = 1) and SecurityLayer >= 2
###############################################################################
try {
    $ua = (Get-ItemProperty -Path $rdpKey -Name UserAuthentication -ErrorAction Stop).UserAuthentication
    $sl = (Get-ItemProperty -Path $rdpKey -Name SecurityLayer -ErrorAction Stop).SecurityLayer
} catch {
    Write-Host "FAIL [PoC]: could not read RDP-Tcp listener settings ($_)."
    exit 1
}
if ($ua -ne 1) {
    Write-Host "FAIL [PoC]: UserAuthentication is $ua (NLA still disabled)."
    exit 1
}
if ($sl -lt 2) {
    Write-Host "FAIL [PoC]: SecurityLayer is $sl (TLS + CredSSP not required)."
    exit 1
}
Write-Host "PASS [PoC]: NLA enabled (UserAuthentication=1, SecurityLayer=$sl)."

###############################################################################
# Regression Check: RDP still enabled and 3389 still listening
###############################################################################
try {
    $deny = (Get-ItemProperty -Path $tsKey -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections
} catch {
    Write-Host "FAIL [Regression]: could not read fDenyTSConnections ($_)."
    exit 1
}
if ($deny -ne 0) {
    Write-Host "FAIL [Regression]: RDP has been disabled entirely (fDenyTSConnections=$deny)."
    exit 1
}
$listening = Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue
if (-not $listening) {
    Write-Host "FAIL [Regression]: nothing listening on TCP/3389."
    exit 1
}
Write-Host "PASS [Regression]: RDP listener still serving on 3389."

Write-Host "All checks passed."
exit 0
