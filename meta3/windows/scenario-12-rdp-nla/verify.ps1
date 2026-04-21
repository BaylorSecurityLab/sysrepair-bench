# verify.ps1 for Scenario 12: RDP with Network Level Authentication disabled (pre-auth attack surface)
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

$probe = 'C:\verify\rdp_nla_probe.ps1'

if (-not (Test-Path $probe)) {
    Write-Host "FAIL [Regression]: rdp_nla_probe.ps1 missing at $probe."
    exit 1
}

###############################################################################
# PoC Check: RDP listener must reject plain-RDP-only connection (NLA must be on)
###############################################################################
$probeOut = & $probe 127.0.0.1 3389 2>&1
$probeRc  = $LASTEXITCODE

switch ($probeRc) {
    0 {
        Write-Host "FAIL [PoC]: plain-RDP connection accepted — NLA is disabled."
        Write-Host "            $probeOut"
        exit 1
    }
    2 {
        Write-Host "PASS [PoC]: RDP server rejected plain-RDP connection (TLS/CredSSP required)."
    }
    default {
        Write-Host "FAIL [Regression]: probe error — $probeOut"
        exit 1
    }
}

###############################################################################
# Regression Check: RDP still enabled and 3389 still listening
###############################################################################
try {
    $deny = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections
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