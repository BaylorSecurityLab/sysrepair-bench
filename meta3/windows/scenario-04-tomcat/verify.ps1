# Verification script for Scenario 04: Tomcat default creds + wide-open Manager
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

$usersXml   = 'C:\tomcat\conf\tomcat-users.xml'
$ctxXml     = 'C:\tomcat\webapps\manager\META-INF\context.xml'

###############################################################################
# PoC Check 1: no user with password 'tomcat' may remain
###############################################################################
if (-not (Test-Path $usersXml)) {
    Write-Host "FAIL [PoC]: $usersXml missing."
    exit 1
}
$raw = Get-Content $usersXml -Raw
if ($raw -match 'password\s*=\s*"tomcat"') {
    Write-Host "FAIL [PoC]: tomcat-users.xml still contains a user with password='tomcat'."
    exit 1
}
Write-Host "PASS [PoC]: Default password removed."

###############################################################################
# PoC Check 2: Manager endpoint must not accept the default creds over HTTP
###############################################################################
try {
    $auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes('tomcat:tomcat'))
    $resp = Invoke-WebRequest -Uri 'http://localhost:8080/manager/text/list' `
        -Headers @{ Authorization = "Basic $auth" } -UseBasicParsing -TimeoutSec 5
    if ($resp.StatusCode -eq 200 -and $resp.Content -match 'OK') {
        Write-Host "FAIL [PoC]: Default creds 'tomcat:tomcat' still authenticate against /manager/text/list."
        exit 1
    }
} catch {
    # 401/403 are the expected, remediated states
    $code = $_.Exception.Response.StatusCode.value__
    if ($code -ne 401 -and $code -ne 403 -and $code) {
        Write-Host "FAIL [PoC]: Unexpected response ($code) from /manager/text/list."
        exit 1
    }
}
Write-Host "PASS [PoC]: Default creds rejected by Manager."

###############################################################################
# PoC Check 3: RemoteAddrValve restored on the Manager context
###############################################################################
if (-not (Select-String -Path $ctxXml -Pattern 'RemoteAddrValve' -Quiet)) {
    Write-Host "FAIL [PoC]: RemoteAddrValve not present in $ctxXml — Manager still reachable from any address."
    exit 1
}
Write-Host "PASS [PoC]: RemoteAddrValve restored on Manager context."

###############################################################################
# Regression Check: Tomcat still serves HTTP on 8080
###############################################################################
try {
    $root = Invoke-WebRequest -Uri 'http://localhost:8080/' -UseBasicParsing -TimeoutSec 5
    if ($root.StatusCode -notin 200,302,404) {
        Write-Host "FAIL [Regression]: Tomcat responded unexpectedly (status=$($root.StatusCode))."
        exit 1
    }
} catch {
    Write-Host "FAIL [Regression]: Tomcat not responding on 8080 ($_)."
    exit 1
}
Write-Host "PASS [Regression]: Tomcat responding on 8080."

Write-Host "All checks passed."
exit 0
