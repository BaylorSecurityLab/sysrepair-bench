# Verification script for Scenario 09: Elasticsearch 1.1.1 dynamic-scripting RCE (CVE-2014-3120)
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

###############################################################################
# PoC Check: version upgraded OR dynamic scripting explicitly disabled
###############################################################################
$fixed = $false
try {
    $resp = Invoke-RestMethod -Uri 'http://localhost:9200/' -TimeoutSec 5
    $ver  = $resp.version.number
    if ($ver) {
        $parts = $ver.Split('.') | ForEach-Object { [int]$_ }
        while ($parts.Count -lt 3) { $parts += 0 }
        # Fixed in 1.2.0 (which changed the default) — accept anything >= 1.2.0
        $fixed = ($parts[0] -gt 1) -or ($parts[0] -eq 1 -and $parts[1] -ge 2)
        if ($fixed) { Write-Host "PASS [PoC]: Elasticsearch version $ver >= 1.2.0." }
    }
} catch {
    Write-Host "FAIL [Regression]: Elasticsearch not responding on 9200 ($_)."
    exit 1
}

if (-not $fixed) {
    # Fall through to the stopgap check: elasticsearch.yml must have script.disable_dynamic: true
    $cfg = 'C:\elasticsearch-1.1.1\config\elasticsearch.yml'
    if (-not (Test-Path $cfg)) {
        Write-Host "FAIL [PoC]: elasticsearch.yml not found and version is still 1.1.x."
        exit 1
    }
    $raw = Get-Content $cfg -Raw
    if ($raw -notmatch '(?m)^\s*script\.disable_dynamic\s*:\s*true') {
        Write-Host "FAIL [PoC]: script.disable_dynamic is not set to true; dynamic scripting is still enabled."
        exit 1
    }
    Write-Host "PASS [PoC]: Dynamic scripting disabled (stopgap remediation)."
}

###############################################################################
# Live PoC Check: a scripted _search request must NOT execute code
###############################################################################
$payload = @{
    size = 1
    query = @{ match_all = @{} }
    script_fields = @{
        rce = @{
            script = 'java.lang.Runtime.getRuntime().exec("whoami").getInputStream()'
        }
    }
} | ConvertTo-Json -Depth 6
try {
    $scriptResp = Invoke-WebRequest -Uri 'http://localhost:9200/_search?pretty' `
        -Method POST -Body $payload -ContentType 'application/json' `
        -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
    if ($scriptResp.StatusCode -eq 200 -and $scriptResp.Content -match '"rce"\s*:\s*\[') {
        Write-Host "FAIL [PoC]: _search still accepts a dynamic script with script_fields."
        exit 1
    }
} catch {
    # 4xx from ES = scripting disallowed, which is exactly what we want
}
Write-Host "PASS [PoC]: _search rejects dynamic script payload."

###############################################################################
# Regression Check: ES still responds to a plain cluster health query
###############################################################################
try {
    $health = Invoke-RestMethod -Uri 'http://localhost:9200/_cluster/health' -TimeoutSec 5
    if (-not $health.cluster_name) {
        Write-Host "FAIL [Regression]: _cluster/health returned unexpected payload."
        exit 1
    }
} catch {
    Write-Host "FAIL [Regression]: ES not responding to /_cluster/health ($_)."
    exit 1
}
Write-Host "PASS [Regression]: Elasticsearch healthy on 9200."

Write-Host "All checks passed."
exit 0
