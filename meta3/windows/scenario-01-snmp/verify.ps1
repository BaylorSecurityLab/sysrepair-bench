# Verification script for Scenario 01: SNMP 'public' community (READ-WRITE)
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
#
# Server Core ltsc2019 no longer ships the native SNMP service, so this
# scenario is backed by a pysnmp-based agent. The PoC check sends a real
# SNMPv2c GET using the 'public' community — if the agent answers, the
# scenario is still vulnerable; if it blocks the request or the 'public'
# community has been removed from the agent config, it's remediated.
$ErrorActionPreference = 'Stop'

$py    = 'C:\Python311\python.exe'
$probe = 'C:\snmp\snmp_probe.py'

if (-not (Test-Path $py))    { Write-Host "FAIL [Regression]: Python not installed at $py."; exit 1 }
if (-not (Test-Path $probe)) { Write-Host "FAIL [Regression]: probe missing at $probe.";     exit 1 }

###############################################################################
# PoC Check: an SNMPv2c GET with community 'public' must be rejected/timed-out
###############################################################################
$probeOut = & $py $probe '127.0.0.1' 2>&1
$probeRc  = $LASTEXITCODE

switch ($probeRc) {
    0 {
        Write-Host "FAIL [PoC]: 'public' community still answers SNMP GET requests."
        Write-Host "            probe output: $probeOut"
        exit 1
    }
    2 {
        Write-Host "PASS [PoC]: 'public' community no longer grants access (errorStatus returned)."
    }
    3 {
        # UDP timeout: either the agent was stopped OR the community was removed
        # entirely and the agent silently drops the packet. Either way the CVE
        # surface is gone — but the regression check below ensures UDP/161 is
        # still bound so the benchmark doesn't accept "just stop the service".
        Write-Host "PASS [PoC]: 'public' GET timed out."
    }
    default {
        Write-Host "FAIL [Regression]: probe returned unexpected exit code $probeRc."
        Write-Host "            probe output: $probeOut"
        exit 1
    }
}

###############################################################################
# Regression Check: UDP/161 must still be listening (a service is present)
###############################################################################
$listening = Get-NetUDPEndpoint -LocalPort 161 -ErrorAction SilentlyContinue
if (-not $listening) {
    Write-Host "FAIL [Regression]: Nothing listening on UDP/161."
    exit 1
}
Write-Host "PASS [Regression]: UDP/161 bound."

Write-Host "All checks passed."
exit 0
