# Verification script for Scenario 02: IIS directory browsing + TRACE
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'
Import-Module WebAdministration -ErrorAction SilentlyContinue

###############################################################################
# PoC Check 1: directory browsing must be OFF on Default Web Site
###############################################################################
$dirBrowse = (Get-WebConfigurationProperty -Filter '/system.webServer/directoryBrowse' `
    -PSPath 'IIS:\Sites\Default Web Site' -Name enabled).Value
if ($dirBrowse -eq $true) {
    Write-Host "FAIL [PoC]: directoryBrowse is still enabled on Default Web Site."
    exit 1
}
Write-Host "PASS [PoC]: directoryBrowse disabled."

###############################################################################
# PoC Check 2: TRACE verb must not be allowed
###############################################################################
$verbs = Get-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' `
    -Filter '/system.webServer/security/requestFiltering/verbs/add'
$traceAllowed = $verbs | Where-Object { $_.verb -eq 'TRACE' -and $_.allowed -eq $true }
if ($traceAllowed) {
    Write-Host "FAIL [PoC]: TRACE verb is still allowed in requestFiltering."
    exit 1
}
Write-Host "PASS [PoC]: TRACE verb not allowed."

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
    # 403/404 throw — treat those as 'site is up, just no default doc' which is fine
    if ($_.Exception.Response.StatusCode.value__ -notin 200,403,404) {
        Write-Host "FAIL [Regression]: HTTP/80 not responding ($_)."
        exit 1
    }
}
Write-Host "PASS [Regression]: HTTP/80 responding."

Write-Host "All checks passed."
exit 0
