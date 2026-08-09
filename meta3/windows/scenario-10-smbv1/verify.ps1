# verify.ps1 for Scenario 10: SMBv1 enabled (EternalBlue precondition; CVE-2017-0144 exposure)
# Two-component verdict: see lib/verifylib.ps1.
#
# CONTAINER LIMITATION (why this checks config state, not a live SMB negotiate):
# The Windows SMB server driver stack cannot load inside a container --
# LanmanServer depends on Srv2 (Server SMB 2.xxx Driver) which depends on the
# srvnet kernel driver, and srvnet.sys fails to start in a container
# ("The dependency service or group failed to start", SCM error 1068). So
# LanmanServer never runs and TCP/445 never listens; a live SMB1 NEGOTIATE probe
# against 445 is impossible here. We therefore assert the *persisted* server
# configuration: EnableSMB1Protocol is stored as the SMB1 DWORD under
# LanmanServer\Parameters -- exactly the value Set-SmbServerConfiguration
# -EnableSMB1Protocol writes -- which is the canonical SMBv1 on/off switch.
$ErrorActionPreference = 'Stop'
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }
$paramKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'

###############################################################################
# A registry value is not guaranteed to be a DWORD. An agent that "fixes" this
# with `reg add ... /t REG_SZ /d 1` leaves a STRING behind, and a bare [int]
# cast on a non-numeric string ("Enabled") is a TERMINATING error under
# $ErrorActionPreference='Stop': the script would die before Complete-Verify,
# no summary would be emitted, and BOTH components would be lost for that
# sample. Parse defensively and let the caller record a FAILED check instead.
#
# A numeric string still reads as its number, so a REG_SZ "0" grades exactly as
# it graded before this guard existed. That is deliberate: [int]'0' already
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

###############################################################################
# PoC Check: the SMB1 server dialect must be disabled (SMB1 registry value = 0).
###############################################################################
$smb1 = (Get-ItemProperty -Path $paramKey -Name 'SMB1' -ErrorAction SilentlyContinue).SMB1
if ($null -eq $smb1) { $smb1 = 0 }   # absent == disabled default on modern Windows
$smb1Num  = ConvertTo-SrDword $smb1
$smb1Type = $smb1.GetType().Name
$typeNote = if ($smb1 -is [int] -or $smb1 -is [long]) { '' } else { " [stored as $smb1Type, not REG_DWORD]" }
if ($null -eq $smb1Num) {
    Record-Poc smb1_disabled 0 "SMB1 value '$smb1' is not a number$typeNote - the SMB server reads this as a DWORD, so SMB1 is not provably disabled."
} elseif ($smb1Num -ne 0) {
    Record-Poc smb1_disabled 0 "SMB1 server protocol still enabled (SMB1=$smb1)$typeNote - EternalBlue precondition present."
} else {
    Record-Poc smb1_disabled 1 "SMB1 server protocol disabled (SMB1=$smb1)$typeNote."
}

###############################################################################
# Regression Check: the remediation must disable SMB1 WITHOUT destroying the
# Server service. It cannot be Running in-container (srvnet won't load), so we
# assert the service still exists and was not taken the lazy way out by setting
# it to Disabled.
###############################################################################
$svc = Get-Service -Name LanmanServer -ErrorAction SilentlyContinue
if (-not $svc) {
    Record-Reg lanmanserver_present 0 "LanmanServer service was removed."
    Record-Reg lanmanserver_not_disabled 0 "LanmanServer service was removed - StartType unreadable."
} else {
    Record-Reg lanmanserver_present 1
    if ($svc.StartType -eq 'Disabled') {
        Record-Reg lanmanserver_not_disabled 0 "LanmanServer set to Disabled - SMB broken rather than SMB1 turned off."
    } else {
        Record-Reg lanmanserver_not_disabled 1 "StartType=$($svc.StartType)."
    }
}

Complete-Verify
