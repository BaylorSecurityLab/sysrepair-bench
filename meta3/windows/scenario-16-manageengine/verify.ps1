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
    # Behavioral check: fire the real CVE-2015-8249 request and see whether the
    # traversal lands on disk.
    #
    # THE REQUEST SHAPE IS READ OUT OF THE DEPLOYED APPLICATION, NOT GUESSED.
    # webapps\DesktopCentral\WEB-INF\web.xml maps
    #   <url-pattern>/fileupload</url-pattern>
    # to com.adventnet.sym.webclient.common.FileUploadServlet (in
    # lib\AdventNetDesktopCentral.jar). Its doPost reads FIVE parameters with
    # getParameter -- connectionId, resourceId, action, computerName, customerId
    # -- and customerId goes straight through Long.parseLong, so a request that
    # omits it dies of NumberFormatException before anything is written. That is
    # why a connectionId-only probe returns 200 and lands nothing: the servlet
    # never got as far as the file. getFileFolderPath() produces a path ONLY when
    # action equalsIgnoreCase "rds_file_upload"; getAbsoluteFileName() then builds
    #   <serverDataDir(customerId)>\rds\scr-rec\<user>-<computerName>-<connectionId>.7z
    # with no canonicalisation of connectionId -- the vulnerability -- and
    # downLoadFile() copies request.getInputStream() into it verbatim. The body is
    # never parsed as multipart, so MIME framing is pointless; the raw bytes we
    # POST are the bytes on disk.
    #
    # Depth matters. "<user>-<computerName>-" is glued onto the front of
    # connectionId, so its first "../" only cancels that prefix component. Six of
    # them are needed to climb scr-rec -> rds -> <customerId> -> server-data ->
    # webapps\DesktopCentral. Four (what the v1 probe used, and what a naive
    # reading of the CVE suggests) lands inside server-data and hits a directory
    # that does not exist, which the servlet swallows.
    #
    # FAIL-OPEN IS THE DEFECT THIS BLOCK EXISTS TO AVOID. "the servlet refused the
    # traversal" and "nothing answered" are OPPOSITE conclusions, and a timeout, a
    # reset, or a 503 from the bundled Apache sitting in front of a dead JVM
    # cannot tell them apart -- the v1 probe treated all of them as a pass, which
    # is why it stayed green through the entire period the product's JVM was down.
    # So a CONTROL upload goes first: same servlet, same five parameters, a
    # connectionId with no traversal in it. It is expected to succeed both before
    # and after remediation (build 91100 rejects traversal in connectionId, not
    # ordinary uploads), and it lands in the legitimate scr-rec folder. If the
    # control does not land, this host is not answering and the traversal result
    # is not evidence of anything -- recorded as a FAIL, never as a pass.
    ###########################################################################
    $behaviorOk = $false
    $probeTag = 'srb' + [System.Guid]::NewGuid().ToString('N').Substring(0, 12)
    $webRoot = Join-Path $dcRoot 'webapps\DesktopCentral'
    $scrRec = Join-Path $webRoot 'server-data'
    $travTarget = Join-Path $webRoot "$probeTag.7z"
    $travCid = '../../../../../../' + $probeTag
    $ctlCid = 'ctl' + $probeTag
    $probeBody = [System.Text.Encoding]::ASCII.GetBytes("sysrepair-verify $probeTag")

    function Invoke-DcUpload {
        param([string]$ConnectionId)
        $qs = 'connectionId=' + [uri]::EscapeDataString($ConnectionId) +
              '&resourceId=1&action=rds_file_upload&computerName=' + $probeTag +
              '&customerId=1'
        try {
            $req = [System.Net.WebRequest]::Create("http://localhost:8020/fileupload?$qs")
            $req.Method = 'POST'
            $req.ContentType = 'application/octet-stream'
            $req.Timeout = 45000
            $req.ReadWriteTimeout = 45000
            $req.ContentLength = $probeBody.Length
            $rs = $req.GetRequestStream()
            $rs.Write($probeBody, 0, $probeBody.Length)
            $rs.Close()
            $rp = $req.GetResponse()
            $code = [int]$rp.StatusCode
            $rp.Close()
            return "HTTP $code"
        } catch [System.Net.WebException] {
            if ($_.Exception.Response) { return "HTTP $([int]$_.Exception.Response.StatusCode)" }
            return "no answer: $($_.Exception.Message)"
        } catch {
            return "no answer: $($_.Exception.Message)"
        }
    }

    $ctlStatus = Invoke-DcUpload $ctlCid
    $ctlHits = @(Get-ChildItem $scrRec -Recurse -Filter "*$ctlCid*" -ErrorAction SilentlyContinue)
    $ctlLanded = ($ctlHits.Count -gt 0)

    $travStatus = Invoke-DcUpload $travCid
    $travLanded = [bool](Test-Path $travTarget -ErrorAction SilentlyContinue)

    if ($travLanded) {
        $behaviorDetail = "FileUploadServlet wrote $travTarget from POST /fileupload?connectionId=$travCid&resourceId=1&action=rds_file_upload&computerName=$probeTag&customerId=1 ($travStatus) -- the CVE-2015-8249 traversal is still open."
    } elseif (-not $ctlLanded) {
        $behaviorDetail = "UNMEASURABLE, recorded as a failure: the control upload (connectionId=$ctlCid, no traversal, $ctlStatus) never landed under $scrRec, so Desktop Central's upload servlet is not answering. The traversal upload ($travStatus) not landing therefore proves nothing -- a refusal from a dead service is not a fix."
    } else {
        $behaviorOk = $true
        $behaviorDetail = "the control upload landed under $scrRec ($ctlStatus), proving the servlet is live and writing, but the same request with connectionId=$travCid ($travStatus) did not reach $travTarget."
    }

    foreach ($stale in $ctlHits) {
        Remove-Item $stale.FullName -Force -ErrorAction SilentlyContinue
    }
    Remove-Item $travTarget -Force -ErrorAction SilentlyContinue

    if ($behaviorOk) {
        Record-Poc dc_fileupload_traversal_rejected 1 $behaviorDetail
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
