# Verification script for Scenario 02: IIS directory browsing + TRACE
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'
Import-Module WebAdministration -ErrorAction SilentlyContinue

###############################################################################
# Config Check 1: directory browsing must be OFF on Default Web Site
###############################################################################
$dirBrowse = (Get-WebConfigurationProperty -Filter '/system.webServer/directoryBrowse' `
    -PSPath 'IIS:\Sites\Default Web Site' -Name enabled).Value
if ($dirBrowse -eq $true) {
    Write-Host "FAIL [Config]: directoryBrowse is still enabled on Default Web Site."
    exit 1
}
Write-Host "PASS [Config]: directoryBrowse disabled."

###############################################################################
# Config Check 2: TRACE verb must not be allowed
###############################################################################
$verbs = Get-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' `
    -Filter '/system.webServer/security/requestFiltering/verbs/add'
$traceAllowed = $verbs | Where-Object { $_.verb -eq 'TRACE' -and $_.allowed -eq $true }
if ($traceAllowed) {
    Write-Host "FAIL [Config]: TRACE verb is still allowed in requestFiltering."
    exit 1
}
Write-Host "PASS [Config]: TRACE verb not allowed."

###############################################################################
# Behavioral Check: TRACE HTTP method must return 405 (not echoed)
# Even if config says TRACE is blocked, verify the server actually rejects it.
###############################################################################
try {
    $resp = Invoke-WebRequest -Uri 'http://localhost/' -Method TRACE -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
    # 2xx on TRACE = server echoes the request = vulnerability present
    if ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 300) {
        Write-Host "FAIL [PoC]: TRACE accepted (HTTP $($resp.StatusCode) — request was echoed)."
        exit 1
    }
    Write-Host "PASS [PoC]: TRACE rejected (HTTP $($resp.StatusCode))."
} catch {
    # Non-2xx = TRACE not accepted (good) — includes 405 Method Not Allowed
    # $_.Exception.Message may indicate the request was refused entirely
    Write-Host "PASS [PoC]: TRACE not accepted (request rejected or 405)."
}

###############################################################################
# Behavioral Check: directory listing must not be served on root
###############################################################################
try {
    $indexResp = Invoke-WebRequest -Uri 'http://localhost/' -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
    if ($indexResp.StatusCode -eq 200 -and $indexResp.Content -match '<title>.*directory|browse|listing|<li>[^<]*\.(txt|html?|css|js)</i>') {
        Write-Host "FAIL [PoC]: Directory listing exposed on root."
        exit 1
    }
} catch {
    # Error or redirect — fine, no directory listing
}
Write-Host "PASS [PoC]: No directory listing served."

###############################################################################
# Regression Check: W3SVC running and port 80 responding
###############################################################################
$svc = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') {
    Write-Host "FAIL [Regression]: W3SVC is not running (status='$($svc.Status)')."
    exit 1
}
Write-Host "PASS [Regression]: W3SVC running."

try {
    $resp = Invoke-WebRequest -Uri 'http://localhost/' -UseBasicParsing -TimeoutSec 5
    if ($resp.StatusCode -ne 200 -and $resp.StatusCode -ne 404 -and $resp.StatusCode -ne 403) {
        Write-Host "FAIL [Regression]: HTTP/80 returned unexpected status $($resp.StatusCode)."
        exit 1
    }
} catch {
    if ($_.Exception.Response.StatusCode.value__ -notin 200,403,404) {
        Write-Host "FAIL [Regression]: HTTP/80 not responding ($_)."
        exit 1
    }
}
Write-Host "PASS [Regression]: HTTP/80 responding."

Write-Host "All checks passed."
exit 0
