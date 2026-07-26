# verify.ps1 for Scenario 11: SMB signing not required (NTLM relay surface)
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
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
$paramKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'

###############################################################################
# PoC Check: SMB server signing must be REQUIRED.
###############################################################################
$reqReg = (Get-ItemProperty -Path $paramKey -Name 'RequireSecuritySignature' -ErrorAction SilentlyContinue).RequireSecuritySignature
$reqCfg = $false
try { $reqCfg = [bool](Get-SmbServerConfiguration -ErrorAction Stop).RequireSecuritySignature } catch {}
if (([int]$reqReg -ne 1) -and (-not $reqCfg)) {
    Write-Host "FAIL [PoC]: SMB signing is not required (RequireSecuritySignature=$reqReg) — NTLM relay downgrade still possible."
    exit 1
}
Write-Host "PASS [PoC]: SMB signing is required (RequireSecuritySignature=1)."

###############################################################################
# Regression Check: LanmanServer must not have been destroyed or disabled. It
# cannot be Running in-container (srvnet won't load), so assert presence + not
# Disabled rather than a live listener.
###############################################################################
$svc = Get-Service -Name LanmanServer -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Host "FAIL [Regression]: LanmanServer service was removed."
    exit 1
}
if ($svc.StartType -eq 'Disabled') {
    Write-Host "FAIL [Regression]: LanmanServer set to Disabled — SMB broken rather than signing required."
    exit 1
}
Write-Host "PASS [Regression]: LanmanServer present and still enabled (StartType=$($svc.StartType))."

Write-Host "All checks passed."
exit 0
