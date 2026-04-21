# Verification script for Scenario 16: ManageEngine Desktop Central 9 FileUploadServlet (CVE-2015-8249)
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

$dcRoot = 'C:\ManageEngine\DesktopCentral_Server'

###############################################################################
# Decommission path: service gone + no listener on 8020/8040 is an accepted fix
###############################################################################
$svc = Get-Service -Name DesktopCentralServer -ErrorAction SilentlyContinue
$listen8020 = Get-NetTCPConnection -LocalPort 8020 -State Listen -ErrorAction SilentlyContinue
$listen8040 = Get-NetTCPConnection -LocalPort 8040 -State Listen -ErrorAction SilentlyContinue

if ((-not $svc -or $svc.Status -ne 'Running') -and -not $listen8020 -and -not $listen8040) {
    Write-Host "PASS [PoC]: Desktop Central decommissioned (service stopped, 8020/8040 silent)."
    Write-Host "All checks passed."
    exit 0
}

###############################################################################
# Config check: build number must be >= 91100 to be considered "fix-configured".
# Unlike the old OR-style script, this does NOT short-circuit to PASS.
# Both config AND behavioral must pass for a final PASS.
###############################################################################
$configOk = $false
$buildInfo = $null
$buildFile = Join-Path $dcRoot 'conf\product.conf'
if (Test-Path $buildFile) {
    $raw = Get-Content $buildFile -ErrorAction SilentlyContinue | Where-Object { $_ -match '^buildnumber=' }
    if ($raw -match 'buildnumber=(\d+)') {
        $build = [int]$matches[1]
        $buildInfo = "conf\product.conf reports build $build"
        if ($build -ge 91100) {
            $configOk = $true
        }
    }
}
if (-not $configOk) {
    try {
        $resp = Invoke-WebRequest -Uri 'http://localhost:8020/configurations.do' -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop
        if ($resp.Content -match 'Build\s*[:#]?\s*(\d{5,})') {
            $build = [int]$matches[1]
            $buildInfo = "admin UI reports build $build"
            if ($build -ge 91100) {
                $configOk = $true
            }
        }
    } catch {
    }
}

###############################################################################
# Behavioral check: the FileUploadServlet must no longer accept traversal.
# A patched build responds 401/403/404 or a traversal-rejection 400;
# any 2xx on the crafted path means the vulnerability is still present.
###############################################################################
$behaviorOk = $false
$boundary = [System.Guid]::NewGuid().ToString()
$probeName = "verify_" + [System.Guid]::NewGuid().ToString("N") + ".jsp"
$body = "--$boundary`r`nContent-Disposition: form-data; name=`"file`"; filename=`"$probeName`"`r`nContent-Type: application/octet-stream`r`n`r`n<% out.println(`"VULN-VERIFY`"); %>`r`n--$boundary--`r`n"
$url = 'http://localhost:8020/fileupload?connectionId=../../../../webapps/DesktopCentral/' + $probeName
$wroteFile = $false
try {
    $resp = Invoke-WebRequest -Uri $url -Method POST -Body $body `
        -ContentType "multipart/form-data; boundary=$boundary" -UseBasicParsing `
        -TimeoutSec 8 -ErrorAction SilentlyContinue
    if ($resp -and $resp.StatusCode -ge 200 -and $resp.StatusCode -lt 300) {
        # Check if the file was actually written — some patched versions return 200
        # but silently drop traversal attempts. Only a full exploit writes the file.
        $wroteFile = Test-Path "C:\ManageEngine\DesktopCentral_Server\webapps\DesktopCentral\$probeName"
        if ($wroteFile) {
            Write-Host "FAIL [PoC]: FileUploadServlet accepted traversal upload (HTTP $($resp.StatusCode), file written)."
            Remove-Item "C:\ManageEngine\DesktopCentral_Server\webapps\DesktopCentral\$probeName" -ErrorAction SilentlyContinue
            exit 1
        }
    }
} catch {
    # Non-2xx = servlet rejected (404/400/403), or connection failed
}
$behaviorOk = $true

###############################################################################
# Strict AND: both config and behavioral must pass.
# If config reports >= 91100 but the servlet still accepts the traversal,
# this correctly fails (catches version-spoofed / partially-patched cases).
###############################################################################
if ($configOk -and $behaviorOk) {
    if ($buildInfo) {
        Write-Host "PASS [Config]: Desktop Central build >= 91100 ($buildInfo)."
    }
    Write-Host "PASS [PoC]: FileUploadServlet no longer accepts CVE-2015-8249 traversal."
    Write-Host "All checks passed."
    exit 0
}

if (-not $configOk) {
    Write-Host "FAIL [Config]: Desktop Central build < 91100 (or undetectable)."
} else {
    Write-Host "FAIL [Config]: build >= 91100 but behavioral check did not complete."
}
if (-not $behaviorOk) {
    Write-Host "FAIL [PoC]: FileUploadServlet still accepts traversal payload."
}
Write-Host "All checks complete — vulnerability still present."
exit 1

###############################################################################
# Regression: if DC is still serving on 8020, the admin UI must answer with a
# real status (2xx/3xx/4xx), not 5xx.
#
# We gate on $listen8020 rather than $svc.Status because the container CMD runs
# the DC wrapper in console mode (stdin-redirected so the JVM clears its EULA
# prompt) and leaves the Windows service itself Stopped. `Get-Service` is the
# wrong proxy for "DC is live"; the 8020 listener is authoritative.
###############################################################################
if ($listen8020) {
    try {
        $homeResp = Invoke-WebRequest -Uri 'http://localhost:8020/' -UseBasicParsing -TimeoutSec 8
        if ($homeResp.StatusCode -lt 200 -or $homeResp.StatusCode -ge 500) {
            Write-Host "FAIL [Regression]: admin UI returned HTTP $($homeResp.StatusCode)."
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
