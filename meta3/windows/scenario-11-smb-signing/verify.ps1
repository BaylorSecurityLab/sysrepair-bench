# verify.ps1 for Scenario 11: SMB signing not required (NTLM relay surface)
# Two-component verdict: see lib/verifylib.ps1.
#
# CONTAINER LIMITATION (why this checks config state, not a live SMB negotiate):
# The Windows SMB server driver stack cannot load inside a container --
# LanmanServer depends on Srv2 which depends on the srvnet kernel driver, and
# srvnet.sys fails to start in a container (SCM error 1068). So LanmanServer never
# runs and TCP/445 never listens; a live SMB2 NEGOTIATE probe against 445 is
# impossible here. We therefore assert the *persisted* server configuration:
# RequireSecuritySignature is stored under LanmanServer\Parameters and is exactly
# what Set-SmbServerConfiguration -RequireSecuritySignature writes.
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

###############################################################################
# PoC Check: SMB server signing must be REQUIRED.
###############################################################################
$reqReg = (Get-ItemProperty -Path $paramKey -Name 'RequireSecuritySignature' -ErrorAction SilentlyContinue).RequireSecuritySignature
$reqCfg = $false
try { $reqCfg = [bool](Get-SmbServerConfiguration -ErrorAction Stop).RequireSecuritySignature } catch {}
$reqNum  = ConvertTo-SrDword $reqReg
$typeNote = if ($null -eq $reqReg -or $reqReg -is [int] -or $reqReg -is [long]) { '' } else { " [stored as $($reqReg.GetType().Name), not REG_DWORD]" }
if (($reqNum -eq 1) -or $reqCfg) {
    Record-Poc smb_signing_required 1 "SMB signing is required (RequireSecuritySignature=$reqReg$typeNote; Get-SmbServerConfiguration reports $reqCfg)."
} elseif (($null -eq $reqNum) -and ($null -ne $reqReg)) {
    Record-Poc smb_signing_required 0 "RequireSecuritySignature value '$reqReg' is not a number$typeNote - the SMB server reads this as a DWORD, so signing is not provably required."
} else {
    Record-Poc smb_signing_required 0 "SMB signing is not required (RequireSecuritySignature=$reqReg) - NTLM relay downgrade still possible."
}

###############################################################################
# Regression Check: LanmanServer must not have been destroyed or disabled. It
# cannot be Running in-container (srvnet won't load), so assert presence + not
# Disabled rather than a live listener.
###############################################################################
$svc = Get-Service -Name LanmanServer -ErrorAction SilentlyContinue
if (-not $svc) {
    Record-Reg lanmanserver_present 0 "LanmanServer service was removed."
    Record-Reg lanmanserver_not_disabled 0 "LanmanServer service was removed - StartType unreadable."
} else {
    Record-Reg lanmanserver_present 1
    if ($svc.StartType -eq 'Disabled') {
        Record-Reg lanmanserver_not_disabled 0 "LanmanServer set to Disabled - SMB broken rather than signing required."
    } else {
        Record-Reg lanmanserver_not_disabled 1 "StartType=$($svc.StartType)."
    }
}

Complete-Verify
