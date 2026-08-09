# Verification script for Scenario 02: IIS directory browsing + TRACE
# Two-component verdict: see lib/verifylib.ps1.
$ErrorActionPreference = 'Stop'
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }
Import-Module WebAdministration -ErrorAction SilentlyContinue

###############################################################################
# PoC Check 1: directory browsing must be OFF on Default Web Site
###############################################################################
# Under 'Stop' this throws outright if the WebAdministration module failed to
# load or the agent deleted the site - both states the benchmark must grade,
# not crash on. Unreadable config cannot prove the vulnerability is closed.
try {
    $dirBrowse = (Get-WebConfigurationProperty -Filter '/system.webServer/directoryBrowse' `
        -PSPath 'IIS:\Sites\Default Web Site' -Name enabled).Value
    if ($dirBrowse -eq $true) {
        Record-Poc dirbrowse_disabled 0 "directoryBrowse is still enabled on Default Web Site."
    } else {
        Record-Poc dirbrowse_disabled 1
    }
} catch {
    Record-Poc dirbrowse_disabled 0 "could not read directoryBrowse config: $($_.Exception.Message)"
}

###############################################################################
# PoC Check 2: TRACE verb must not be allowed
###############################################################################
try {
    $verbs = Get-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' `
        -Filter '/system.webServer/security/requestFiltering/verbs/add'
    $traceAllowed = $verbs | Where-Object { $_.verb -eq 'TRACE' -and $_.allowed -eq $true }
    if ($traceAllowed) {
        Record-Poc trace_verb_denied 0 "TRACE verb is still allowed in requestFiltering."
    } else {
        Record-Poc trace_verb_denied 1
    }
} catch {
    Record-Poc trace_verb_denied 0 "could not read requestFiltering verbs: $($_.Exception.Message)"
}

###############################################################################
# Behavioral PoC Check: TRACE HTTP method must return 405 (not echoed)
# Even if config says TRACE is blocked, verify the server actually rejects it.
###############################################################################
try {
    $resp = Invoke-WebRequest -Uri 'http://localhost/' -Method TRACE -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
    # 2xx on TRACE = server echoes the request = vulnerability present
    if ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 300) {
        Record-Poc trace_rejected 0 "TRACE accepted (HTTP $($resp.StatusCode) - request was echoed)."
    } else {
        Record-Poc trace_rejected 1 "TRACE rejected (HTTP $($resp.StatusCode))."
    }
} catch {
    # Non-2xx = TRACE not accepted (good) - includes 405 Method Not Allowed
    # $_.Exception.Message may indicate the request was refused entirely
    Record-Poc trace_rejected 1 "TRACE not accepted (request rejected or 405)."
}

###############################################################################
# Behavioral PoC Check: directory listing must not be served on root
###############################################################################
$listingExposed = $false
try {
    $indexResp = Invoke-WebRequest -Uri 'http://localhost/' -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
    if ($indexResp.StatusCode -eq 200 -and $indexResp.Content -match '<title>.*directory|browse|listing|<li>[^<]*\.(txt|html?|css|js)</i>') {
        $listingExposed = $true
    }
} catch {
    # Error or redirect - fine, no directory listing
}
if ($listingExposed) { Record-Poc no_directory_listing 0 "Directory listing exposed on root." }
else                 { Record-Poc no_directory_listing 1 }

###############################################################################
# Regression Check: W3SVC running and port 80 responding
###############################################################################
$svc = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Record-Reg w3svc_running 1
} else {
    Record-Reg w3svc_running 0 "W3SVC is not running (status='$($svc.Status)')."
}

$httpOk = $true
$httpWhy = ''
try {
    $resp = Invoke-WebRequest -Uri 'http://localhost/' -UseBasicParsing -TimeoutSec 5
    if ($resp.StatusCode -ne 200 -and $resp.StatusCode -ne 404 -and $resp.StatusCode -ne 403) {
        $httpOk = $false
        $httpWhy = "HTTP/80 returned unexpected status $($resp.StatusCode)."
    }
} catch {
    if ($_.Exception.Response.StatusCode.value__ -notin 200,403,404) {
        $httpOk = $false
        $httpWhy = "HTTP/80 not responding ($($_.Exception.Message))."
    }
}
if ($httpOk) { Record-Reg http_80_responding 1 }
else         { Record-Reg http_80_responding 0 $httpWhy }

Complete-Verify
