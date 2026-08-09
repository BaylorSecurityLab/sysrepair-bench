# Verification script for Scenario 01: SNMP 'public' community (READ-WRITE)
# Two-component verdict: see lib/verifylib.ps1.
#
# Server Core ltsc2019 no longer ships the native SNMP service, so this
# scenario is backed by a pysnmp-based agent. The PoC check sends a real
# SNMPv2c GET using the 'public' community - if the agent answers, the
# scenario is still vulnerable; if it blocks the request or the 'public'
# community has been removed from the agent config, it's remediated.
$ErrorActionPreference = 'Stop'
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }

$py    = 'C:\Python311\python.exe'
$probe = 'C:\snmp\snmp_probe.py'

###############################################################################
# Regression Checks: the pysnmp toolchain that backs this scenario must survive.
###############################################################################
$pyOk = Test-Path $py
if ($pyOk) { Record-Reg python_present 1 }
else       { Record-Reg python_present 0 "Python not installed at $py." }

$probeOk = Test-Path $probe
if ($probeOk) { Record-Reg probe_present 1 }
else          { Record-Reg probe_present 0 "probe missing at $probe." }

###############################################################################
# PoC Check: an SNMPv2c GET with community 'public' must be rejected/timed-out
###############################################################################
# The probe is a native command run under $ErrorActionPreference='Stop' with
# 2>&1: in Windows PowerShell 5.1 that wraps stderr lines in ErrorRecords and
# terminates the script. It also throws outright when $py is missing - exactly
# the state this benchmark has to GRADE. Hence the try/catch.
$probeOut = ''
$probeRc  = -1
if ($pyOk -and $probeOk) {
    try {
        $global:LASTEXITCODE = 0
        $probeOut = (& $py $probe '127.0.0.1' 2>&1 | Out-String).Trim()
        $probeRc  = $global:LASTEXITCODE
    } catch {
        $probeOut = "probe threw: $($_.Exception.Message)"
        $probeRc  = -1
    }
} else {
    $probeOut = 'probe toolchain missing; SNMP state could not be observed'
}

switch ($probeRc) {
    0 {
        Record-Poc snmp_public_rejected 0 "'public' community still answers SNMP GET requests. probe output: $probeOut"
    }
    2 {
        Record-Poc snmp_public_rejected 1
    }
    3 {
        # UDP timeout: either the agent was stopped OR the community was removed
        # entirely and the agent silently drops the packet. Either way the CVE
        # surface is gone - but the regression check below ensures UDP/161 is
        # still bound so the benchmark doesn't accept "just stop the service".
        Record-Poc snmp_public_rejected 1 "'public' GET timed out."
    }
    default {
        Record-Poc snmp_public_rejected 0 "probe returned unexpected exit code $probeRc. probe output: $probeOut"
    }
}

###############################################################################
# Regression Check: UDP/161 must still be listening (a service is present)
###############################################################################
$listening = Get-NetUDPEndpoint -LocalPort 161 -ErrorAction SilentlyContinue
if ($listening) { Record-Reg udp161_bound 1 }
else            { Record-Reg udp161_bound 0 "Nothing listening on UDP/161." }

Complete-Verify
