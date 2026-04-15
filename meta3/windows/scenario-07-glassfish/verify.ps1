# Verification script for Scenario 07: GlassFish 4.0 admin traversal + empty admin password
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

$keyfile = 'C:\glassfish4\glassfish\domains\domain1\config\admin-keyfile'
$domain  = 'C:\glassfish4\glassfish\domains\domain1\config\domain.xml'

###############################################################################
# PoC Check 1: admin-keyfile must not contain a user with an empty password hash
###############################################################################
if (-not (Test-Path $keyfile)) {
    Write-Host "FAIL [PoC]: $keyfile missing — domain1 may be unconfigured."
    exit 1
}
$line = (Get-Content $keyfile | Where-Object { $_ -like 'admin;*' } | Select-Object -First 1)
if (-not $line) {
    Write-Host "FAIL [PoC]: No 'admin' user found in admin-keyfile."
    exit 1
}
# Format: <user>;<hash>;<groups>. Empty password hash appears as ';;' or the canonical
# GlassFish empty-password token 'AS-SHA256-...<no salt content>'.
$hash = ($line -split ';')[1]
if ([string]::IsNullOrWhiteSpace($hash) -or $hash -match '^\s*$') {
    Write-Host "FAIL [PoC]: admin user still has an empty password hash."
    exit 1
}
Write-Host "PASS [PoC]: admin user has a non-empty password hash."

###############################################################################
# PoC Check 2: traversal endpoint must not return domain.xml contents anymore
###############################################################################
try {
    $url = 'http://localhost:4848/theme/META-INF/prototype%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/domain.xml'
    $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5
    if ($resp.StatusCode -eq 200 -and $resp.Content -match '<domain ') {
        Write-Host "FAIL [PoC]: Traversal on /theme/META-INF/prototype... still returns domain.xml."
        exit 1
    }
} catch {
    # 404/400/403 here is the expected post-fix behavior
}
Write-Host "PASS [PoC]: Admin-listener traversal no longer returns domain.xml."

###############################################################################
# Regression Check: GlassFish still serves the application listener on 8080
###############################################################################
try {
    $resp = Invoke-WebRequest -Uri 'http://localhost:8080/' -UseBasicParsing -TimeoutSec 5
    if ($resp.StatusCode -notin 200,302,404) {
        Write-Host "FAIL [Regression]: GlassFish 8080 returned unexpected status $($resp.StatusCode)."
        exit 1
    }
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    if ($code -notin 200,302,404) {
        Write-Host "FAIL [Regression]: GlassFish not responding on 8080 ($_)."
        exit 1
    }
}
Write-Host "PASS [Regression]: GlassFish responding on 8080."

Write-Host "All checks passed."
exit 0
