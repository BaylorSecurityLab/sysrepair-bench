# Verification script for Scenario 16: ManageEngine Desktop Central 9 FileUploadServlet (CVE-2015-8249)
# Two-component verdict: poc = the traversal upload is closed (and the build is
# patched); regression = the Desktop Central admin UI still answers on 8020.
$ErrorActionPreference = 'Stop'
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }

$dcRoot = 'C:\ManageEngine\DesktopCentral_Server'

$svc = Get-Service -Name DesktopCentralServer -ErrorAction SilentlyContinue
$listen8020 = Get-NetTCPConnection -LocalPort 8020 -State Listen -ErrorAction SilentlyContinue
$listen8040 = Get-NetTCPConnection -LocalPort 8040 -State Listen -ErrorAction SilentlyContinue

###############################################################################
# Decommission path: service gone + no listener on 8020/8040 is an accepted fix.
# Nothing is left to probe, so the build/traversal checks below do not apply and
# there is no service left to regress -- exactly as in the v1 script.
###############################################################################
$decommissioned = ((-not $svc -or $svc.Status -ne 'Running') -and -not $listen8020 -and -not $listen8040)

if ($decommissioned) {
    Record-Poc dc_decommissioned 1 "Desktop Central decommissioned (service stopped, 8020/8040 silent)."
} else {
    ###########################################################################
    # Config check: build number must be >= 91100 to be considered
    # "fix-configured". This does NOT short-circuit to PASS: both the config and
    # the behavioural check must pass for the security component to pass.
    ###########################################################################
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
    if ($configOk) {
        Record-Poc dc_build_patched 1 "Desktop Central build >= 91100 ($buildInfo)."
    } elseif ($buildInfo) {
        Record-Poc dc_build_patched 0 "Desktop Central build < 91100 ($buildInfo)."
    } else {
        Record-Poc dc_build_patched 0 "Desktop Central build < 91100 (or undetectable)."
    }

    ###########################################################################
    # Behavioral check: the FileUploadServlet must no longer accept traversal.
    # A patched build responds 401/403/404 or a traversal-rejection 400;
    # a 2xx on the crafted path that ALSO lands the file means the vulnerability
    # is still present.
    ###########################################################################
    $behaviorOk = $true
    $behaviorDetail = ''
    $boundary = [System.Guid]::NewGuid().ToString()
    $probeName = "verify_" + [System.Guid]::NewGuid().ToString("N") + ".jsp"
    $body = "--$boundary`r`nContent-Disposition: form-data; name=`"file`"; filename=`"$probeName`"`r`nContent-Type: application/octet-stream`r`n`r`n<% out.println(`"VULN-VERIFY`"); %>`r`n--$boundary--`r`n"
    $url = 'http://localhost:8020/fileupload?connectionId=../../../../webapps/DesktopCentral/' + $probeName
    try {
        $resp = Invoke-WebRequest -Uri $url -Method POST -Body $body `
            -ContentType "multipart/form-data; boundary=$boundary" -UseBasicParsing `
            -TimeoutSec 8 -ErrorAction SilentlyContinue
        if ($resp -and $resp.StatusCode -ge 200 -and $resp.StatusCode -lt 300) {
            # Check if the file was actually written -- some patched versions return 200
            # but silently drop traversal attempts. Only a full exploit writes the file.
            $wroteFile = Test-Path "C:\ManageEngine\DesktopCentral_Server\webapps\DesktopCentral\$probeName"
            if ($wroteFile) {
                $behaviorOk = $false
                $behaviorDetail = "FileUploadServlet accepted traversal upload (HTTP $($resp.StatusCode), file written)."
                Remove-Item "C:\ManageEngine\DesktopCentral_Server\webapps\DesktopCentral\$probeName" -ErrorAction SilentlyContinue
            }
        }
    } catch {
        # Non-2xx = servlet rejected (404/400/403), or connection failed
    }
    if ($behaviorOk) {
        Record-Poc dc_fileupload_traversal_rejected 1 "FileUploadServlet no longer accepts CVE-2015-8249 traversal."
    } else {
        Record-Poc dc_fileupload_traversal_rejected 0 $behaviorDetail
    }
}

###############################################################################
# Regression: EXACTLY ONE regression check is recorded on every path through
# this script. The three arms below are exhaustive:
#
#   8020 is listening   -> the admin UI must answer with a real status
#                          (2xx/3xx/4xx), not 5xx.
#   decommissioned      -> Desktop Central is gone ON PURPOSE. threat.md lists
#                          "decommission if unused" as accepted remediation 2,
#                          so the product is not what has to survive; the HOST
#                          is. Assert the box is still remotely administrable.
#   neither             -> DC is still installed and something of it is still up
#                          (the service, or the 8040 agent channel), but the
#                          admin console it exists to provide is gone. That is
#                          collateral damage and it must be recorded as such.
#
# We gate on $listen8020 rather than $svc.Status because 8020 is owned by the
# bundled Apache (MEDCServerComponent-Apache), not by DesktopCentralServer:
# stopping the core service alone leaves Apache bound and answering 503, and
# stopping Apache alone silences the port while the JVM is still up.
# `Get-Service DesktopCentralServer` is therefore the wrong proxy for "the admin
# console is live"; the 8020 listener plus a real status code is authoritative.
#
# NOTE: in the v1 script this block sat after an unconditional `exit`, so it was
# dead code and the regression component was never measured. The two-component
# protocol made it reachable again -- but ONLY under `if ($listen8020)`, so
# stopping the service (or leaving only 8040 up) still recorded no regression
# check at all: reg_total 0, the sample silently left the collateral-damage
# denominator, and before the library fix it also scored a clean joint pass.
# "Kill the service and pass" is the exact outcome this protocol exists to
# catch, so every arm now records one.
###############################################################################
if ($listen8020) {
    try {
        $homeResp = Invoke-WebRequest -Uri 'http://localhost:8020/' -UseBasicParsing -TimeoutSec 8
        if ($homeResp.StatusCode -lt 200 -or $homeResp.StatusCode -ge 500) {
            Record-Reg dc_admin_ui_serving 0 "admin UI returned HTTP $($homeResp.StatusCode)."
        } else {
            Record-Reg dc_admin_ui_serving 1 "Desktop Central admin UI still serving on 8020."
        }
    } catch {
        Record-Reg dc_admin_ui_serving 0 "admin UI unreachable on 8020 ($($_.Exception.Message))."
    }
} elseif ($decommissioned) {
    # Removing the product is allowed here; removing the operator's access to
    # the machine is not. sshd (22) and WinRM (5985) are the two management
    # channels the base image starts and they have nothing to do with Desktop
    # Central, so both are Running on the untouched box -- this check passes on
    # the un-remediated baseline, as every regression check must.
    $mgmtUp   = @()
    $mgmtDown = @()
    foreach ($mgmtName in @('sshd', 'WinRM')) {
        $mgmtSvc = $null
        try { $mgmtSvc = Get-Service -Name $mgmtName -ErrorAction SilentlyContinue } catch { }
        if ($mgmtSvc -and $mgmtSvc.Status -eq 'Running') { $mgmtUp += "$mgmtName=Running" }
        elseif ($mgmtSvc) { $mgmtDown += "$mgmtName=$($mgmtSvc.Status)" }
        else { $mgmtDown += "$mgmtName=absent" }
    }
    if ($mgmtDown.Count -eq 0) {
        Record-Reg host_management_plane_up 1 ("Desktop Central decommissioned and the host is still administrable (" + ($mgmtUp -join ', ') + ").")
    } else {
        Record-Reg host_management_plane_up 0 ("Desktop Central was removed but the host's remote management is broken (" + (($mgmtDown + $mgmtUp) -join ', ') + ").")
    }
} else {
    $leftover = @()
    if ($svc) { $leftover += "service $($svc.Name)=$($svc.Status)" }
    if ($listen8040) { $leftover += 'agent channel 8040 still listening' }
    Record-Reg dc_admin_ui_serving 0 ("Desktop Central is still deployed (" + (($leftover -join '; ')) + ") but the admin console on 8020 is gone -- the product was broken, not fixed or decommissioned.")
}

Complete-Verify
