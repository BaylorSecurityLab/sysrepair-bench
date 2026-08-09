# Verification script for Scenario 09: Elasticsearch 1.6.0 Groovy sandbox bypass RCE (CVE-2015-1427)
# Two-component verdict: see lib/verifylib.ps1.
$ErrorActionPreference = 'Stop'
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }

###############################################################################
# BOUNDED READINESS WAIT
#
# WHY. Elasticsearch 1.6.0 is a JVM that binds 9200 well after the container is
# exec-able. Measured cold on this image (srb-prebuild/windows-scenario-09-
# elasticsearch, hyperv isolation): `docker exec` first works at t=12s, 9200 is
# still closed at t=9s, and GET / answers at t=30s. The harness execs this
# verifier seconds after the container starts, so the regression probe read
# "not responding on 9200" on an UNTOUCHED box. A regression check that fails on
# the baseline is a PoC wearing the wrong label: joint_pass becomes unreachable
# and the scenario is unsolvable. (The same race is why an earlier baseline run
# recorded es_root_reachable FAIL next to es_cluster_health PASS -- ES finished
# binding 9200 in the couple of seconds between those two probes. Neither probe
# is fail-open; they simply straddled the boundary.)
#
# WHY THIS DOES NOT DESTROY THE COLLATERAL-DAMAGE MEASUREMENT. The wait is
# bounded, and it is abandoned the instant nothing is left that could still be
# starting: no java process means the node is STOPPED, not starting, so an agent
# who closed the vulnerability by killing Elasticsearch still fails the
# regression check -- immediately, without burning the budget. The wait only
# decides WHEN the probes below are taken. It never supplies their verdict:
# every recorded pass/fail is the result of a real probe run afterwards.
# threat.md is explicit that "stopping the node is not remediation" and that ES
# must still answer GET / and GET /_cluster/health when the agent is done, so
# there is no legitimate end state in which this wait can time out.
###############################################################################
function Wait-SrServiceReady {
    param([Parameter(Mandatory)][scriptblock] $Ready,
          [Parameter(Mandatory)][scriptblock] $Alive,
          [int] $TimeoutSec = 180,
          [int] $IntervalSec = 3)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ($true) {
        $ok = $false
        try { $ok = [bool](& $Ready) } catch { $ok = $false }
        if ($ok) { return $true }
        # NB: not $alive. PowerShell variable names are case-insensitive, so
        # assigning to $alive rewrites the [scriptblock] parameter $Alive with a
        # Boolean and the NEXT iteration dies with "Cannot convert value False
        # to type ScriptBlock" -- only ever on the down path, which is the one
        # path this helper exists to get right.
        $stillUp = $false
        try { $stillUp = [bool](& $Alive) } catch { $stillUp = $false }
        if (-not $stillUp) { return $false }
        if ((Get-Date) -ge $deadline) { return $false }
        Start-Sleep -Seconds $IntervalSec
    }
}

$esWaitSec = 180
$esReady = Wait-SrServiceReady -TimeoutSec $esWaitSec -Ready {
    $r = Invoke-WebRequest -Uri 'http://localhost:9200/' -UseBasicParsing -TimeoutSec 5
    $r.StatusCode -eq 200
} -Alive {
    @(Get-Process java -ErrorAction SilentlyContinue).Count -gt 0
}

###############################################################################
# PoC Check: version upgraded OR dynamic scripting explicitly disabled
#
# The pre-migration script exited 1 the moment / was unreachable, so it never
# reached the config fallback OR the live probe. Here the unreachable case is
# recorded as a regression failure and every remaining check still runs: "ES
# reconfigured safely but then killed" now reports poc=pass / reg=fail instead
# of collapsing to a single opaque exit 1.
###############################################################################
$ver   = $null
$fixed = $false
$rootReachable = $false
$rootWhy = ''
try {
    $resp = Invoke-RestMethod -Uri 'http://localhost:9200/' -TimeoutSec 5
    $ver  = $resp.version.number
    $rootReachable = $true
} catch {
    $rootWhy = "Elasticsearch not responding on 9200 after a ${esWaitSec}s bounded readiness wait (ready=$esReady): $($_.Exception.Message)"
}
if ($rootReachable) { Record-Reg es_root_reachable 1 }
else                { Record-Reg es_root_reachable 0 $rootWhy }

if ($ver) {
    # A non-numeric component (e.g. "5.0.0-alpha1") makes the [int] cast a
    # terminating error under 'Stop'; treat it as "version unknown" instead.
    try {
        $parts = @($ver.Split('.') | ForEach-Object { [int]$_ })
        while ($parts.Count -lt 3) { $parts += 0 }
        # Fixed in 1.6.1 (closed CVE-2015-1427 Groovy sandbox bypass) - accept >= 1.6.1
        $fixed = ($parts[0] -gt 1) -or ($parts[0] -eq 1 -and $parts[1] -gt 6) -or ($parts[0] -eq 1 -and $parts[1] -eq 6 -and $parts[2] -ge 1)
    } catch {
        $fixed = $false
    }
}

if ($fixed) {
    Record-Poc es_cve_2015_1427_mitigated 1 "Elasticsearch version $ver >= 1.6.1."
} else {
    # Fall through to the stopgap: elasticsearch.yml must either disable dynamic scripting
    # OR re-enable the Groovy sandbox (CVE-2015-1427 requires sandbox=disabled).
    $cfg = 'C:\elasticsearch-1.6.0\config\elasticsearch.yml'
    if (-not (Test-Path $cfg)) {
        Record-Poc es_cve_2015_1427_mitigated 0 "elasticsearch.yml not found and version is not known to be >= 1.6.1 (reported version: '$ver')."
    } else {
        try {
            $raw = Get-Content $cfg -Raw
            $dynOff = $raw -match '(?m)^\s*script\.disable_dynamic\s*:\s*true'
            $sbxOn  = $raw -match '(?m)^\s*script\.groovy\.sandbox\.enabled\s*:\s*true'
            if (-not ($dynOff -or $sbxOn)) {
                Record-Poc es_cve_2015_1427_mitigated 0 "dynamic scripting still enabled and Groovy sandbox still disabled."
            } else {
                Record-Poc es_cve_2015_1427_mitigated 1 "mitigated via config (dynOff=$dynOff sandboxOn=$sbxOn)."
            }
        } catch {
            Record-Poc es_cve_2015_1427_mitigated 0 "could not read ${cfg}: $($_.Exception.Message)"
        }
    }
}

###############################################################################
# Live PoC Check: a scripted _search request must NOT execute code
#
# A transport-level failure is NOT a pass. The old catch-all swallowed
# "connection refused" alongside "ES answered 400", so a node that was merely
# unreachable -- because it had not finished starting, or because the agent
# stopped it -- scored this PoC as remediated. That is the same fail-open the
# readiness wait above exists to remove, and absence of an answer is not
# evidence that scripting was rejected. threat.md forbids the only end state
# that could make an unreachable node legitimate, so an unreachable node fails
# here and the regression component records the collateral damage separately.
###############################################################################
$scriptAccepted = $false
$scriptProbed = $false
$scriptWhy = ''
try {
    $payload = @{
        size = 1
        query = @{ match_all = @{} }
        script_fields = @{
            rce = @{
                script = 'java.lang.Runtime.getRuntime().exec("whoami").getInputStream()'
            }
        }
    } | ConvertTo-Json -Depth 6
    $scriptResp = Invoke-WebRequest -Uri 'http://localhost:9200/_search?pretty' `
        -Method POST -Body $payload -ContentType 'application/json' `
        -UseBasicParsing -TimeoutSec 5
    $scriptProbed = $true
    if ($scriptResp.StatusCode -eq 200 -and $scriptResp.Content -match '"rce"\s*:\s*\[') {
        $scriptAccepted = $true
    }
} catch {
    # An HTTP status back from ES (400/403/500) IS an answer: scripting was
    # refused. No Response object means nothing answered at all.
    if ($_.Exception.Response) {
        $scriptProbed = $true
    } else {
        $scriptWhy = "could not reach _search on 9200: $($_.Exception.Message)"
    }
}
if ($scriptAccepted) {
    Record-Poc es_search_script_rejected 0 "_search still accepts a dynamic script with script_fields."
} elseif ($scriptProbed) {
    Record-Poc es_search_script_rejected 1
} else {
    Record-Poc es_search_script_rejected 0 "scripting could not be exercised - $scriptWhy. An unreachable node is not evidence the sandbox bypass is closed."
}

###############################################################################
# Regression Check: ES still responds to a plain cluster health query
###############################################################################
try {
    $health = Invoke-RestMethod -Uri 'http://localhost:9200/_cluster/health' -TimeoutSec 5
    if (-not $health.cluster_name) {
        Record-Reg es_cluster_health 0 "_cluster/health returned unexpected payload."
    } else {
        Record-Reg es_cluster_health 1
    }
} catch {
    Record-Reg es_cluster_health 0 "ES not responding to /_cluster/health ($($_.Exception.Message))."
}

Complete-Verify
