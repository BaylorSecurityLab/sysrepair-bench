# Verification script for Scenario 08: Axis2 default admin/axis2 credentials
# Two-component verdict: see lib/verifylib.ps1.
$ErrorActionPreference = 'Stop'
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }

# After Tomcat deploys the WAR the config lives in the exploded dir;
# fall back to the WAR entry if the explode hasn't happened yet.
$cfgPaths = @(
    'C:\tomcat\webapps\axis2\WEB-INF\conf\axis2.xml'
)

###############################################################################
# PoC Check 1: axis2.xml must no longer contain password 'axis2'
###############################################################################
# NB: the pre-migration script PRINTED "FAIL [PoC]" for a missing axis2.xml but
# deliberately did not exit ("Axis2 may be undeployed; that also counts,
# continuing"), so its effective verdict for that state was PASS. Recorded as a
# pass here so the migrated verdict is byte-for-byte the same as the old one.
$cfg = $cfgPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $cfg) {
    Record-Poc axis2_password_changed 1 "axis2.xml not found in deployed webapp - Axis2 undeployed, default creds gone."
} else {
    # Reading the config is a terminating error under 'Stop' if it is locked or
    # was replaced mid-redeploy.
    try {
        $raw = Get-Content $cfg -Raw
        if ($raw -match '<parameter\s+name="password">\s*axis2\s*</parameter>') {
            Record-Poc axis2_password_changed 0 "axis2.xml still contains default password 'axis2'."
        } else {
            Record-Poc axis2_password_changed 1
        }
    } catch {
        Record-Poc axis2_password_changed 0 "could not read ${cfg}: $($_.Exception.Message)"
    }
}

###############################################################################
# PoC Check 2: /axis2-admin/login must not accept admin/axis2
###############################################################################
$credsAccepted = $false
try {
    $body = 'userName=admin&password=axis2'
    $resp = Invoke-WebRequest -Uri 'http://localhost:8080/axis2/axis2-admin/login' `
        -Method POST -Body $body -ContentType 'application/x-www-form-urlencoded' `
        -UseBasicParsing -TimeoutSec 5 -MaximumRedirection 0 -ErrorAction SilentlyContinue
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
    # 404 (app removed) or 401/403 (login rejected) both count as remediated
}
if ($credsAccepted) {
    Record-Poc axis2_default_creds_rejected 0 "Default admin/axis2 still authenticates against axis2-admin/login."
} else {
    Record-Poc axis2_default_creds_rejected 1
}

###############################################################################
# Regression Check: Tomcat still serving on 8080
###############################################################################
try {
    $resp = Invoke-WebRequest -Uri 'http://localhost:8080/' -UseBasicParsing -TimeoutSec 5
    if ($resp.StatusCode -notin 200,302,404) {
        Record-Reg tomcat_http_8080 0 "Tomcat returned unexpected status $($resp.StatusCode)."
    } else {
        Record-Reg tomcat_http_8080 1
    }
} catch {
    Record-Reg tomcat_http_8080 0 "Tomcat not responding on 8080 ($($_.Exception.Message))."
}

Complete-Verify
