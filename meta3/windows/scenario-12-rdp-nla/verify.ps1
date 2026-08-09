# verify.ps1 for Scenario 12: RDP with Network Level Authentication disabled (pre-auth attack surface)
# Two-component verdict: see lib/verifylib.ps1.
#
# CONTAINER LIMITATION (why this checks config state, not a live X.224 probe):
# Remote Desktop Services (TermService) cannot start inside a Windows container
# ("Cannot start service TermService on computer '.'"; it ships Stopped/Disabled),
# so TCP/3389 never listens and a live TPKT/X.224 RDP negotiation probe is
# impossible here. We therefore assert the enforced RDP-Tcp security policy that
# the listener would read per connection: NLA/CredSSP required (UserAuthentication=1)
# and TLS required at the security layer (SecurityLayer>=2).
$ErrorActionPreference = 'Stop'
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }
$rdpTcp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$tsBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'

###############################################################################
# A registry value is not guaranteed to be a DWORD. An agent that "fixes" this
# with `reg add ... /t REG_SZ /d 1` leaves a STRING behind, and a bare [int]
# cast on a non-numeric string ("Enabled") is a TERMINATING error under
# $ErrorActionPreference='Stop': the script would die before Complete-Verify,
# no summary would be emitted, and BOTH components would be lost for that
# sample. Parse defensively and let the caller record a FAILED check instead.
#
# A numeric string still reads as its number, so a REG_SZ "1" grades exactly as
# it graded before this guard existed. That is deliberate: [int]'1' already
# succeeded, so tightening it here would quietly change what counts as
# remediated, which is a grading-semantics decision, not a crash fix. The
# storage type is reported in the detail so a reviewer can see the sloppiness.
# Returns $null when the value cannot be read as a number.
###############################################################################
function ConvertTo-SrDword {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { if ($Value) { return [int64]1 } else { return [int64]0 } }
    $s = ("$Value").Trim()
    $n = [int64]0
    if ([int64]::TryParse($s, [ref]$n)) { return $n }
    # PowerShell's own [int] cast accepts '0x1', so accept it too rather than
    # narrowing. The length bound keeps ToInt64 from overflowing.
    if ($s -match '^0[xX][0-9a-fA-F]{1,15}$') {
        try { return [Convert]::ToInt64($s.Substring(2), 16) } catch { return $null }
    }
    return $null
}

function Get-SrTypeNote {
    param($Value)
    if ($null -eq $Value -or $Value -is [int] -or $Value -is [long]) { return '' }
    return " [stored as $($Value.GetType().Name), not REG_DWORD]"
}

###############################################################################
# PoC Check: NLA (UserAuthentication=1) must be enforced, and the security layer
# must require TLS (SecurityLayer>=2) so plain-RDP negotiation is rejected.
###############################################################################
$ua = (Get-ItemProperty -Path $rdpTcp -Name 'UserAuthentication' -ErrorAction SilentlyContinue).UserAuthentication
$sl = (Get-ItemProperty -Path $rdpTcp -Name 'SecurityLayer' -ErrorAction SilentlyContinue).SecurityLayer
$uaNum = ConvertTo-SrDword $ua
$slNum = ConvertTo-SrDword $sl
$uaNote = Get-SrTypeNote $ua
$slNote = Get-SrTypeNote $sl

if ($null -eq $uaNum) {
    Record-Poc nla_required 0 "UserAuthentication is absent or not a number (value '$ua')$uaNote - the RDP listener reads this as a DWORD, so NLA is not provably enforced."
} elseif ($uaNum -ne 1) {
    Record-Poc nla_required 0 "NLA disabled (UserAuthentication=$ua)$uaNote - pre-auth RDP surface still exposed."
} else {
    Record-Poc nla_required 1 "NLA/CredSSP required (UserAuthentication=$ua)$uaNote."
}

if ($null -eq $slNum) {
    Record-Poc rdp_tls_required 0 "SecurityLayer is absent or not a number (value '$sl')$slNote - the RDP listener reads this as a DWORD, so TLS is not provably required."
} elseif ($slNum -lt 2) {
    Record-Poc rdp_tls_required 0 "RDP security layer does not require TLS (SecurityLayer=$sl)$slNote - plain RDP still negotiable."
} else {
    Record-Poc rdp_tls_required 1 "TLS required (SecurityLayer=$sl)$slNote."
}

###############################################################################
# Regression Check: RDP must not have been "fixed" by disabling it entirely.
# (3389 cannot listen in-container because TermService can't start, so we assert
# fDenyTSConnections=0 rather than a live listener.)
###############################################################################
$deny    = $null
$denyErr = ''
try {
    $deny = (Get-ItemProperty -Path $tsBase -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections
} catch {
    $denyErr = $_.Exception.Message
}
if ($null -eq $deny) {
    Record-Reg rdp_not_disabled 0 "could not read fDenyTSConnections ($denyErr)."
} elseif ($deny -ne 0) {
    Record-Reg rdp_not_disabled 0 "RDP has been disabled entirely (fDenyTSConnections=$deny)."
} else {
    Record-Reg rdp_not_disabled 1 "RDP remains enabled (fDenyTSConnections=0)."
}

Complete-Verify
