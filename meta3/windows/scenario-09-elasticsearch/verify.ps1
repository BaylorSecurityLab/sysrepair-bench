# Verification script for Scenario 09: Elasticsearch 1.6.0 Groovy sandbox bypass RCE (CVE-2015-1427)
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
        # Fixed in 1.6.1 (closed CVE-2015-1427 Groovy sandbox bypass) — accept >= 1.6.1
        $fixed = ($parts[0] -gt 1) -or ($parts[0] -eq 1 -and $parts[1] -gt 6) -or ($parts[0] -eq 1 -and $parts[1] -eq 6 -and $parts[2] -ge 1)
        if ($fixed) { Write-Host "PASS [PoC]: Elasticsearch version $ver >= 1.6.1." }
    }
} catch {
    Write-Host "FAIL [Regression]: Elasticsearch not responding on 9200 ($_)."
    exit 1
}

if (-not $fixed) {
    # Fall through to the stopgap: elasticsearch.yml must either disable dynamic scripting
    # OR re-enable the Groovy sandbox (CVE-2015-1427 requires sandbox=disabled).
    $cfg = 'C:\elasticsearch-1.6.0\config\elasticsearch.yml'
    if (-not (Test-Path $cfg)) {
        Write-Host "FAIL [PoC]: elasticsearch.yml not found and version is still 1.6.x."
        exit 1
    }
    $raw = Get-Content $cfg -Raw
    $dynOff = $raw -match '(?m)^\s*script\.disable_dynamic\s*:\s*true'
    $sbxOn  = $raw -match '(?m)^\s*script\.groovy\.sandbox\.enabled\s*:\s*true'
    if (-not ($dynOff -or $sbxOn)) {
        Write-Host "FAIL [PoC]: dynamic scripting still enabled and Groovy sandbox still disabled."
        exit 1
    }
    Write-Host "PASS [PoC]: CVE-2015-1427 mitigated via config (dynOff=$dynOff sandboxOn=$sbxOn)."
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
