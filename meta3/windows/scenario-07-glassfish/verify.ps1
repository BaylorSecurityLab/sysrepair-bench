# Verification script for Scenario 07: GlassFish 4.0 admin traversal + empty admin password
# Two-component verdict: see lib/verifylib.ps1.
$ErrorActionPreference = 'Stop'
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }

$keyfile = 'C:\glassfish4\glassfish\domains\domain1\config\admin-keyfile'
$domain  = 'C:\glassfish4\glassfish\domains\domain1\config\domain.xml'

###############################################################################
# PoC Check 1: admin-keyfile must not contain a user with an empty password hash
###############################################################################
# The keyfile existing and carrying an 'admin' entry is an integrity property:
# both hold on the untouched vulnerable box and only break when domain1's realm
# is destroyed, so they are regression checks. Either failure still fails the
# PoC, because an unreadable realm is not evidence the empty password is gone.
if (-not (Test-Path $keyfile)) {
    Record-Reg admin_keyfile_present 0 "$keyfile missing - domain1 may be unconfigured."
    Record-Reg admin_user_present 0 "$keyfile missing - no 'admin' user could be read."
    Record-Poc admin_password_not_empty 0 "$keyfile missing - admin password hash could not be inspected."
} else {
    Record-Reg admin_keyfile_present 1
    # Reading the keyfile is a terminating error under 'Stop' if it is locked or
    # was replaced with a directory - both states an agent can leave behind.
    $line = $null
    $readErr = ''
    try {
        $line = (Get-Content $keyfile | Where-Object { $_ -like 'admin;*' } | Select-Object -First 1)
    } catch {
        $readErr = $_.Exception.Message
    }
    if (-not $line) {
        Record-Reg admin_user_present 0 "No 'admin' user found in admin-keyfile. $readErr"
        Record-Poc admin_password_not_empty 0 "No 'admin' user found in admin-keyfile - password hash could not be inspected. $readErr"
    } else {
        Record-Reg admin_user_present 1
        # Format: <user>;<hash>;<groups>. Empty password hash appears as ';;' or the canonical
        # GlassFish empty-password token 'AS-SHA256-...<no salt content>'.
        $hash = ($line -split ';')[1]
        if ([string]::IsNullOrWhiteSpace($hash) -or $hash -match '^\s*$') {
            Record-Poc admin_password_not_empty 0 "admin user still has an empty password hash."
        } else {
            Record-Poc admin_password_not_empty 1
        }
    }
}

###############################################################################
# PoC Check 2: traversal endpoint must not return domain.xml contents anymore
###############################################################################
$traversalOpen = $false
try {
    $url = 'http://localhost:4848/theme/META-INF/prototype%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/domain.xml'
    $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5
    if ($resp.StatusCode -eq 200 -and $resp.Content -match '<domain ') {
        $traversalOpen = $true
    }
} catch {
    # 404/400/403 here is the expected post-fix behavior
}
if ($traversalOpen) {
    Record-Poc admin_traversal_blocked 0 "Traversal on /theme/META-INF/prototype... still returns domain.xml."
} else {
    Record-Poc admin_traversal_blocked 1
}

###############################################################################
# Regression Check: GlassFish still serves the application listener on 8080
###############################################################################
$gfOk = $true
$gfWhy = ''
try {
    $resp = Invoke-WebRequest -Uri 'http://localhost:8080/' -UseBasicParsing -TimeoutSec 5
    if ($resp.StatusCode -notin 200,302,404) {
        $gfOk = $false
        $gfWhy = "GlassFish 8080 returned unexpected status $($resp.StatusCode)."
    }
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    if ($code -notin 200,302,404) {
        $gfOk = $false
        $gfWhy = "GlassFish not responding on 8080 ($($_.Exception.Message))."
    }
}
if ($gfOk) { Record-Reg glassfish_http_8080 1 }
else       { Record-Reg glassfish_http_8080 0 $gfWhy }

Complete-Verify
