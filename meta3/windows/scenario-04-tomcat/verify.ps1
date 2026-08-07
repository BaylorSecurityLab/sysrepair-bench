# Verification script for Scenario 04: Tomcat default creds + wide-open Manager
# Two-component verdict: see lib/verifylib.ps1.
$ErrorActionPreference = 'Stop'
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }

$usersXml   = 'C:\tomcat\conf\tomcat-users.xml'
$ctxXml     = 'C:\tomcat\webapps\manager\META-INF\context.xml'

###############################################################################
# PoC Check 1: no user with password 'tomcat' may remain
###############################################################################
# tomcat-users.xml existing is an integrity property: it holds on the untouched
# vulnerable box and only breaks when the realm file is destroyed, so it is a
# regression check. Not being able to read it still fails the PoC, because an
# unreadable realm is not evidence the default credential is gone.
if (Test-Path $usersXml) {
    Record-Reg users_xml_present 1
    # Reading the file is a terminating error under 'Stop' if it vanished or is
    # locked; an unreadable realm file cannot prove the default cred is gone.
    try {
        $raw = Get-Content $usersXml -Raw
        if ($raw -match 'password\s*=\s*"tomcat"') {
            Record-Poc default_password_removed 0 "tomcat-users.xml still contains a user with password='tomcat'."
        } else {
            Record-Poc default_password_removed 1
        }
    } catch {
        Record-Poc default_password_removed 0 "could not read ${usersXml}: $($_.Exception.Message)"
    }
} else {
    Record-Reg users_xml_present 0 "$usersXml missing."
    Record-Poc default_password_removed 0 "$usersXml missing - cannot confirm the default password was removed."
}

###############################################################################
# PoC Check 2: Manager endpoint must not accept the default creds over HTTP
###############################################################################
$credsAccepted = $false
$credsWhy      = ''
try {
    $auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes('tomcat:tomcat'))
    $resp = Invoke-WebRequest -Uri 'http://localhost:8080/manager/text/list' `
        -Headers @{ Authorization = "Basic $auth" } -UseBasicParsing -TimeoutSec 5
    if ($resp.StatusCode -eq 200 -and $resp.Content -match 'OK') {
        $credsAccepted = $true
        $credsWhy = "Default creds 'tomcat:tomcat' still authenticate against /manager/text/list."
    }
} catch {
    # 401/403 are the expected, remediated states
    $code = $_.Exception.Response.StatusCode.value__
    if ($code -ne 401 -and $code -ne 403 -and $code) {
        $credsAccepted = $true
        $credsWhy = "Unexpected response ($code) from /manager/text/list."
    }
}
if ($credsAccepted) { Record-Poc default_creds_rejected 0 $credsWhy }
else                { Record-Poc default_creds_rejected 1 }

###############################################################################
# PoC Check 3: RemoteAddrValve restored on the Manager context
###############################################################################
# The original called Select-String on $ctxXml unguarded: under 'Stop' that
# THROWS when an agent deletes the manager webapp, killing the script before
# the regression component was ever measured.
try {
    if (-not (Test-Path $ctxXml)) {
        Record-Poc remoteaddrvalve_present 0 "$ctxXml missing - Manager context could not be inspected."
    } elseif (Select-String -Path $ctxXml -Pattern 'RemoteAddrValve' -Quiet) {
        Record-Poc remoteaddrvalve_present 1
    } else {
        Record-Poc remoteaddrvalve_present 0 "RemoteAddrValve not present in $ctxXml - Manager still reachable from any address."
    }
} catch {
    Record-Poc remoteaddrvalve_present 0 "could not inspect ${ctxXml}: $($_.Exception.Message)"
}

###############################################################################
# Regression Check: Tomcat still serves HTTP on 8080
###############################################################################
try {
    $root = Invoke-WebRequest -Uri 'http://localhost:8080/' -UseBasicParsing -TimeoutSec 5
    if ($root.StatusCode -notin 200,302,404) {
        Record-Reg tomcat_http_8080 0 "Tomcat responded unexpectedly (status=$($root.StatusCode))."
    } else {
        Record-Reg tomcat_http_8080 1
    }
} catch {
    Record-Reg tomcat_http_8080 0 "Tomcat not responding on 8080 ($($_.Exception.Message))."
}

Complete-Verify
