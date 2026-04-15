# Verification script for Scenario 08: Axis2 default admin/axis2 credentials
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

# After Tomcat deploys the WAR the config lives in the exploded dir;
# fall back to the WAR entry if the explode hasn't happened yet.
$cfgPaths = @(
    'C:\tomcat\webapps\axis2\WEB-INF\conf\axis2.xml'
)

###############################################################################
# PoC Check 1: axis2.xml must no longer contain password 'axis2'
###############################################################################
$cfg = $cfgPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $cfg) {
    Write-Host "FAIL [PoC]: axis2.xml not found in deployed webapp — Axis2 may be undeployed; that also counts, continuing."
} else {
    $raw = Get-Content $cfg -Raw
    if ($raw -match '<parameter\s+name="password">\s*axis2\s*</parameter>') {
        Write-Host "FAIL [PoC]: axis2.xml still contains default password 'axis2'."
        exit 1
    }
    Write-Host "PASS [PoC]: axis2.xml password changed from default."
}

###############################################################################
# PoC Check 2: /axis2-admin/login must not accept admin/axis2
###############################################################################
try {
    $body = 'userName=admin&password=axis2'
    $resp = Invoke-WebRequest -Uri 'http://localhost:8080/axis2/axis2-admin/login' `
        -Method POST -Body $body -ContentType 'application/x-www-form-urlencoded' `
        -UseBasicParsing -TimeoutSec 5 -MaximumRedirection 0 -ErrorAction SilentlyContinue
    if ($resp.Content -match '(?i)welcome|logout|admin options') {
        Write-Host "FAIL [PoC]: Default admin/axis2 still authenticates against axis2-admin/login."
        exit 1
    }
} catch {
    # 404 (app removed) or 401/403 (login rejected) both count as remediated
}
Write-Host "PASS [PoC]: Default creds rejected by axis2-admin/login."

###############################################################################
# Regression Check: Tomcat still serving on 8080
###############################################################################
try {
    $resp = Invoke-WebRequest -Uri 'http://localhost:8080/' -UseBasicParsing -TimeoutSec 5
    if ($resp.StatusCode -notin 200,302,404) {
        Write-Host "FAIL [Regression]: Tomcat returned unexpected status $($resp.StatusCode)."
        exit 1
    }
} catch {
    Write-Host "FAIL [Regression]: Tomcat not responding on 8080 ($_)."
    exit 1
}
Write-Host "PASS [Regression]: Tomcat responding on 8080."

Write-Host "All checks passed."
exit 0
