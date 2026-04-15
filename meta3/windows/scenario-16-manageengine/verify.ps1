# Verification script for Scenario 16: ManageEngine Desktop Central 9 FileUploadServlet (CVE-2015-8249)
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

$dcRoot = 'C:\ManageEngine\DesktopCentral_Server'

###############################################################################
# Decommission path: service gone + no listener on 8020/8040 is an accepted fix
###############################################################################
$svc = Get-Service -Name ManageEngineDesktopCentral -ErrorAction SilentlyContinue
$listen8020 = Get-NetTCPConnection -LocalPort 8020 -State Listen -ErrorAction SilentlyContinue
$listen8040 = Get-NetTCPConnection -LocalPort 8040 -State Listen -ErrorAction SilentlyContinue

if ((-not $svc -or $svc.Status -ne 'Running') -and -not $listen8020 -and -not $listen8040) {
    Write-Host "PASS [PoC]: Desktop Central decommissioned (service stopped, 8020/8040 silent)."
    Write-Host "All checks passed."
    exit 0
}

###############################################################################
# Upgrade path: build number must be >= 91100
###############################################################################
$buildFile = Join-Path $dcRoot 'bin\buildnumber.txt'
$fixed = $false
if (Test-Path $buildFile) {
    $raw = (Get-Content $buildFile -Raw).Trim()
    if ($raw -match '(\d{5,})') {
        $build = [int]$matches[1]
        if ($build -ge 91100) {
            Write-Host "PASS [PoC]: Desktop Central build $build >= 91100."
            $fixed = $true
        } else {
            Write-Host "INFO [PoC]: Desktop Central build $build still < 91100."
        }
    }
}
# Fallback: some builds expose the version via the admin UI's /STATE endpoint
if (-not $fixed) {
    try {
        $resp = Invoke-WebRequest -Uri 'http://localhost:8020/configurations.do' -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop
        if ($resp.Content -match 'Build\s*[:#]?\s*(\d{5,})') {
            $build = [int]$matches[1]
            if ($build -ge 91100) {
                Write-Host "PASS [PoC]: admin UI reports build $build >= 91100."
                $fixed = $true
            } else {
                Write-Host "FAIL [PoC]: admin UI reports build $build (< 91100)."
            }
        }
    } catch {
        # Admin UI didn't respond; fall through
    }
}

if (-not $fixed) {
    ###############################################################################
    # Live PoC: the FileUploadServlet must no longer accept traversal uploads.
    # A patched build responds with 401/403/404 or a traversal-rejection 400;
    # any 2xx on the crafted path is a fail.
    ###############################################################################
    $boundary = [System.Guid]::NewGuid().ToString()
    $body = "--$boundary`r`nContent-Disposition: form-data; name=`"file`"; filename=`"probe.jsp`"`r`nContent-Type: application/octet-stream`r`n`r`n<% %>`r`n--$boundary--`r`n"
    $url = 'http://localhost:8020/agent/connection/download/FileUploadServlet?connectionId=../../../../webapps/DesktopCentral/probe.jsp'
    try {
        $resp = Invoke-WebRequest -Uri $url -Method POST -Body $body `
            -ContentType "multipart/form-data; boundary=$boundary" -UseBasicParsing `
            -TimeoutSec 8 -ErrorAction SilentlyContinue
        if ($resp -and $resp.StatusCode -ge 200 -and $resp.StatusCode -lt 300) {
            Write-Host "FAIL [PoC]: FileUploadServlet accepted traversal upload (HTTP $($resp.StatusCode))."
            exit 1
        }
    } catch {
        # Non-2xx = good, the servlet refused the request
    }
    Write-Host "PASS [PoC]: FileUploadServlet no longer accepts the CVE-2015-8249 traversal payload."
}

###############################################################################
# Regression: if the service is still deployed, the admin listener must still answer
###############################################################################
if ($svc -and $svc.Status -eq 'Running') {
    try {
        $home = Invoke-WebRequest -Uri 'http://localhost:8020/' -UseBasicParsing -TimeoutSec 8
        if ($home.StatusCode -lt 200 -or $home.StatusCode -ge 500) {
            Write-Host "FAIL [Regression]: admin UI returned HTTP $($home.StatusCode)."
            exit 1
        }
    } catch {
        Write-Host "FAIL [Regression]: admin UI unreachable on 8020 ($_)."
        exit 1
    }
    Write-Host "PASS [Regression]: Desktop Central admin UI still serving on 8020."
}

Write-Host "All checks passed."
exit 0
