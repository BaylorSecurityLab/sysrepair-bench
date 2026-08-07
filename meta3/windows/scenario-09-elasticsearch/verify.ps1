# Verification script for Scenario 09: Elasticsearch 1.6.0 Groovy sandbox bypass RCE (CVE-2015-1427)
# Two-component verdict: see lib/verifylib.ps1.
$ErrorActionPreference = 'Stop'
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }

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
    $rootWhy = "Elasticsearch not responding on 9200 ($($_.Exception.Message))."
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
###############################################################################
$scriptAccepted = $false
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
        -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
    if ($scriptResp.StatusCode -eq 200 -and $scriptResp.Content -match '"rce"\s*:\s*\[') {
        $scriptAccepted = $true
    }
} catch {
    # 4xx from ES = scripting disallowed, which is exactly what we want
}
if ($scriptAccepted) {
    Record-Poc es_search_script_rejected 0 "_search still accepts a dynamic script with script_fields."
} else {
    Record-Poc es_search_script_rejected 1
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
