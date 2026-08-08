# Verification script for Scenario 08: Axis2 default admin/axis2 credentials
# Two-component verdict: see lib/verifylib.ps1.
$ErrorActionPreference = 'Stop'
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }

$cfgPath = 'C:\tomcat\webapps\axis2\WEB-INF\conf\axis2.xml'
$warPath = 'C:\tomcat\webapps\axis2.war'

###############################################################################
# BOUNDED READINESS WAIT
#
# WHY. Tomcat expands axis2.war asynchronously after it starts, and the harness
# execs this verifier seconds after the container comes up. Measured cold on
# this image (srb-prebuild/windows-scenario-08-axis2, hyperv isolation):
# `docker exec` first works at t=12s, at which point axis2.war is present but
# C:\tomcat\webapps\axis2\ does NOT exist yet; the exploded webapp and its
# axis2.xml appear by t=22s. The old script read that gap as remediation --
# "axis2.xml not found in deployed webapp - Axis2 undeployed, default creds
# gone" -- and awarded BOTH PoC checks on a box where nobody had changed
# anything. That is fail-open: absence of the artifact was graded as its
# removal.
#
# WHY THIS DOES NOT DESTROY THE COLLATERAL-DAMAGE MEASUREMENT. The wait is
# bounded and it is abandoned the instant no java process is left, so an agent
# who "fixed" this by killing Tomcat fails the regression check immediately
# rather than after the full budget. The wait decides only WHEN the probes
# below run; it never supplies a verdict.
#
# The ready condition is deliberately two-sided so a legitimate remediation is
# not punished by it: either the exploded config exists (Tomcat finished the
# deployment) or axis2.war is gone (the agent removed the application, and no
# amount of waiting will ever make the config appear).
###############################################################################
function Wait-SrServiceReady {
    param([Parameter(Mandatory)][scriptblock] $Ready,
          [Parameter(Mandatory)][scriptblock] $Alive,
          [int] $TimeoutSec = 120,
          [int] $IntervalSec = 3)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ($true) {
        $ok = $false
        try { $ok = [bool](& $Ready) } catch { $ok = $false }
        if ($ok) { return $true }
        # NB: not $alive. PowerShell variable names are case-insensitive, so
        # assigning to $alive rewrites the [scriptblock] parameter $Alive with a
        # Boolean and the NEXT iteration dies with "Cannot convert value False
        # to type ScriptBlock" -- only ever on the down path, which is the one
        # path this helper exists to get right.
        $stillUp = $false
        try { $stillUp = [bool](& $Alive) } catch { $stillUp = $false }
        if (-not $stillUp) { return $false }
        if ((Get-Date) -ge $deadline) { return $false }
        Start-Sleep -Seconds $IntervalSec
    }
}

$waitSec = 120
$deployReady = Wait-SrServiceReady -TimeoutSec $waitSec -Ready {
    $r = Invoke-WebRequest -Uri 'http://localhost:8080/' -UseBasicParsing -TimeoutSec 5
    ($r.StatusCode -in 200, 302, 404) -and ((Test-Path $cfgPath) -or -not (Test-Path $warPath))
} -Alive {
    @(Get-Process java -ErrorAction SilentlyContinue).Count -gt 0
}

# Observe the box once, after the wait, and grade from that observation.
$tomcatUp = $false
$tomcatWhy = ''
try {
    $rootResp = Invoke-WebRequest -Uri 'http://localhost:8080/' -UseBasicParsing -TimeoutSec 5
    if ($rootResp.StatusCode -in 200, 302, 404) { $tomcatUp = $true }
    else { $tomcatWhy = "Tomcat returned unexpected status $($rootResp.StatusCode)." }
} catch {
    $tomcatWhy = "Tomcat not responding on 8080 ($($_.Exception.Message))."
}
$cfgPresent = Test-Path $cfgPath
$warPresent = Test-Path $warPath

###############################################################################
# UNDECIDABLE STATE -> HARNESS ERROR, NOT A VERDICT.
#
# Tomcat is answering, axis2.war is still deployed, and after the bounded wait
# it has still not been expanded. Nothing an agent does produces that state:
# removing the application removes the WAR, and breaking Tomcat stops it
# answering. It is a deployment that never finished, so the vulnerability this
# scenario grades is not present on the box to be graded. Exit 42 (NOANSWER)
# says "this host could not be graded" and drops the sample from the
# denominator. Grading it either way would be a lie -- and grading it as a PASS
# is precisely the fail-open being removed here.
###############################################################################
if (-not $deployReady -and $tomcatUp -and $warPresent -and -not $cfgPresent) {
    Skip-NotApplicable "Tomcat is serving on 8080 but has not expanded axis2.war after ${waitSec}s; Axis2 is not deployed, so its default credentials are not present to grade."
}

###############################################################################
# PoC Check 1: the deployed axis2.xml must no longer carry password 'axis2'
###############################################################################
if ($cfgPresent) {
    # Reading the config is a terminating error under 'Stop' if it is locked or
    # was replaced mid-redeploy.
    try {
        $raw = Get-Content $cfgPath -Raw
        if ($raw -match '<parameter\s+name="password">\s*axis2\s*</parameter>') {
            Record-Poc axis2_password_changed 0 "axis2.xml still contains default password 'axis2'."
        } else {
            Record-Poc axis2_password_changed 1
        }
    } catch {
        Record-Poc axis2_password_changed 0 "could not read ${cfgPath}: $($_.Exception.Message)"
    }
} elseif ($warPresent) {
    # The WAR is still deployed but its config could not be read. Reached only
    # when Tomcat is NOT serving (the branch above absorbs the timing race), so
    # this is a broken or stopped Tomcat, not an undeployment. An unreadable
    # config is not evidence the default password is gone.
    Record-Poc axis2_password_changed 0 "axis2.war is still deployed but its config is unreadable and Tomcat is not serving ($tomcatWhy) - the default password could not be shown to be gone."
} else {
    # Both the WAR and the exploded webapp are gone. That is a state change an
    # agent had to make: Tomcat never deletes its own WAR, so this cannot be the
    # not-yet-deployed race.
    Record-Poc axis2_password_changed 1 "axis2.war and the exploded webapp are both absent - Axis2 undeployed, default creds gone."
}

###############################################################################
# PoC Check 2: /axis2-admin/login must not accept admin/axis2
#
# A transport-level failure is NOT a pass. The old catch-all treated "connection
# refused" the same as "Tomcat answered 404/401", so an unreachable Tomcat --
# still starting, or stopped by the agent -- scored the credentials as
# remediated. Only an actual HTTP answer proves the login was refused.
###############################################################################
$credsAccepted = $false
$loginProbed = $false
$loginWhy = ''
try {
    $body = 'userName=admin&password=axis2'
    $resp = Invoke-WebRequest -Uri 'http://localhost:8080/axis2/axis2-admin/login' `
        -Method POST -Body $body -ContentType 'application/x-www-form-urlencoded' `
        -UseBasicParsing -TimeoutSec 10 -MaximumRedirection 0
    $loginProbed = $true
    # NB: the Axis2 admin LOGIN page itself carries the banner "Welcome to Axis2 Web Admin
    # Module" and, on a rejected login, the "invalid auth ... Login" error - so matching
    # "welcome"/"login" false-positives on a FAILED login. The admin CONSOLE shown only
    # after a SUCCESSFUL login is what proves the creds worked: it lists the deployed
    # services and a Logout link ("Available Services", "Upload Service", "Logout",
    # "admin options"). Discriminate on those success-only markers.
    if ($resp.Content -match '(?i)logout|admin options|available services|upload service') {
        $credsAccepted = $true
    }
} catch {
    # 404 (app removed), 401/403 (login rejected) and the 3xx that
    # -MaximumRedirection 0 turns into a throw all carry a Response: Tomcat
    # answered and did not hand over the admin console. No Response object at
    # all means nothing answered, which proves nothing.
    if ($_.Exception.Response) {
        $loginProbed = $true
    } else {
        $loginWhy = $_.Exception.Message
    }
}
if ($credsAccepted) {
    Record-Poc axis2_default_creds_rejected 0 "Default admin/axis2 still authenticates against axis2-admin/login."
} elseif ($loginProbed) {
    Record-Poc axis2_default_creds_rejected 1
} else {
    Record-Poc axis2_default_creds_rejected 0 "the axis2-admin login endpoint could not be exercised ($loginWhy) - an unreachable Tomcat is not evidence the default credentials were changed."
}

###############################################################################
# Regression Check: Tomcat still serving on 8080
###############################################################################
if ($tomcatUp) { Record-Reg tomcat_http_8080 1 }
else           { Record-Reg tomcat_http_8080 0 $tomcatWhy }

Complete-Verify
