# Verification script for Scenario 07: GlassFish 4.1.1 admin traversal + empty admin password
# Two-component verdict: see lib/verifylib.ps1.
$ErrorActionPreference = 'Stop'
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }

$keyfile = 'C:\glassfish4\glassfish\domains\domain1\config\admin-keyfile'
# The SSHA256 of the EMPTY password exactly as GlassFish 4.1.1 ships it in
# domain1. Its presence is the shipped-vulnerable state; changing the admin
# password rewrites this field with a fresh salt, so any other value is evidence
# the credential was actually changed.
$shippedEmptyHash = '{SSHA256}nd85GyUoUi+YSE8Oj0w1xIVDoYTH6+i69ZX423kXeWWQvAZrY1Msvw=='

###############################################################################
# BOUNDED READINESS WAIT
#
# WHY. domain1 is a JVM started by `asadmin start-domain` from the entrypoint;
# it binds 4848 and 8080 well after the container is exec-able, and the harness
# execs this verifier seconds after the container starts. The regression probe
# therefore read "GlassFish not responding on 8080" on an UNTOUCHED box, and a
# regression check that fails on the baseline is a PoC wearing the wrong label:
# joint_pass is unreachable and the scenario is unsolvable.
#
# WHY IT DOES NOT DESTROY THE COLLATERAL-DAMAGE MEASUREMENT. The wait is bounded
# and abandoned the instant no java process is left: an agent who stopped the
# domain fails the regression check immediately rather than after the full
# budget. The wait decides only WHEN the probes below run; every recorded
# pass/fail is the result of a real probe taken afterwards.
###############################################################################
function Wait-SrServiceReady {
    param([Parameter(Mandatory)][scriptblock] $Ready,
          [Parameter(Mandatory)][scriptblock] $Alive,
          [int] $TimeoutSec = 240,
          [int] $IntervalSec = 5)
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

$gfWaitSec = 240
$gfReady = Wait-SrServiceReady -TimeoutSec $gfWaitSec -Ready {
    @(Get-NetTCPConnection -LocalPort 8080 -State Listen -ErrorAction SilentlyContinue).Count -gt 0
} -Alive {
    @(Get-Process java -ErrorAction SilentlyContinue).Count -gt 0
}

# Basic-auth probe helper. Returns the HTTP status as an int, or 0 when nothing
# answered at all (which is never treated as evidence of remediation).
function Invoke-SrAuthProbe {
    param([string] $Url, [string] $User, [string] $Pass)
    $headers = @{}
    if ($User) {
        $b = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${User}:${Pass}"))
        $headers['Authorization'] = "Basic $b"
    }
    try {
        $r = Invoke-WebRequest -Uri $Url -Headers $headers -UseBasicParsing -TimeoutSec 10
        return [int]$r.StatusCode
    } catch {
        if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode.value__ }
        return 0
    }
}

###############################################################################
# PoC Check 1: the DAS admin credential must no longer be the empty password
#
# The old check looked for an EMPTY HASH FIELD in admin-keyfile. That is not a
# test of the password: GlassFish stores the empty password as a perfectly
# normal SSHA256 hash, so the shipped-vulnerable box passed it -- which is why
# the image used to overwrite the keyfile with the unparseable 'admin;;asadmin'
# just to make the check fail, and that in turn stopped domain1 from starting at
# all. Both halves of this check are now real evidence:
#
#   * behavioural - authenticate to the DAS REST API as admin with an EMPTY
#     password (and with no credentials at all, which the empty password also
#     enables). A 2xx means the empty password still opens the admin API.
#   * config      - the admin line still carries the hash GlassFish ships for the
#     empty password, or carries no hash at all.
#
# Either one failing fails the check. Neither can be satisfied by the service
# merely being unreachable: an unanswered probe returns 0 and is ignored, and the
# config half is then the only evidence left, so "stop the domain" cannot pass
# this. The keyfile existing and carrying an 'admin' entry stays a REGRESSION
# property: both hold on the untouched vulnerable box and only break when
# domain1's realm is destroyed.
###############################################################################
$hashField = $null
$keyfileReadable = $false
if (-not (Test-Path $keyfile)) {
    Record-Reg admin_keyfile_present 0 "$keyfile missing - domain1 may be unconfigured."
    Record-Reg admin_user_present 0 "$keyfile missing - no 'admin' user could be read."
} else {
    Record-Reg admin_keyfile_present 1
    # Reading the keyfile is a terminating error under 'Stop' if it is locked or
    # was replaced with a directory - both states an agent can leave behind.
    $line = $null
    $readErr = ''
    try {
        $line = (Get-Content $keyfile | Where-Object { $_ -like 'admin;*' } | Select-Object -First 1)
        $keyfileReadable = $true
    } catch {
        $readErr = $_.Exception.Message
    }
    if (-not $line) {
        Record-Reg admin_user_present 0 "No 'admin' user found in admin-keyfile. $readErr"
    } else {
        Record-Reg admin_user_present 1
        # Format: <user>;<hash>;<groups>.
        $hashField = ($line -split ';')[1]
    }
}

$adminUrl = 'http://localhost:4848/management/domain'
$statusEmpty = Invoke-SrAuthProbe -Url $adminUrl -User 'admin' -Pass ''
$statusNone  = Invoke-SrAuthProbe -Url $adminUrl -User '' -Pass ''
if ($statusEmpty -eq 0 -and $statusNone -eq 0) {
    # secure-admin enable is a legitimate remediation and moves 4848 to HTTPS,
    # so a dead plaintext listener is retried over TLS before it is written off.
    try {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        $httpsUrl = 'https://localhost:4848/management/domain'
        $statusEmpty = Invoke-SrAuthProbe -Url $httpsUrl -User 'admin' -Pass ''
        $statusNone  = Invoke-SrAuthProbe -Url $httpsUrl -User '' -Pass ''
    } catch {
    }
}

$emptyAuthWorks = ($statusEmpty -ge 200 -and $statusEmpty -lt 300) -or ($statusNone -ge 200 -and $statusNone -lt 300)
$hashIsShippedEmpty = ([string]::IsNullOrWhiteSpace($hashField)) -or ($hashField.Trim() -eq $shippedEmptyHash)

if ($emptyAuthWorks) {
    Record-Poc admin_password_not_empty 0 "the DAS admin API still accepts the empty admin password (admin:<empty> -> $statusEmpty, no credentials -> $statusNone)."
} elseif ($hashIsShippedEmpty) {
    $shown = if ([string]::IsNullOrWhiteSpace($hashField)) { '<empty>' } else { 'the shipped empty-password SSHA256' }
    Record-Poc admin_password_not_empty 0 "admin-keyfile still stores $shown for user 'admin' (live probe: admin:<empty> -> $statusEmpty, no credentials -> $statusNone)."
} elseif (-not $keyfileReadable -and $statusEmpty -eq 0 -and $statusNone -eq 0) {
    Record-Poc admin_password_not_empty 0 "neither the admin listener nor admin-keyfile could be read, so the empty admin password could not be shown to be gone."
} else {
    Record-Poc admin_password_not_empty 1 "admin credential changed (admin:<empty> -> $statusEmpty, no credentials -> $statusNone)."
}

###############################################################################
# PoC Check 2: traversal endpoint must not return domain.xml contents anymore
#
# MEASURED CAVEAT: on this image, with domain1 up, the overlong-UTF-8 form
# answers 404 -- Grizzly rejects the %c0%ae sequences before the console's
# resource servlet sees them - so this check already passes on the untouched
# box. It is kept because it is the only direct probe of CVE-2017-1000028 and it
# can still catch a build where the traversal does resolve; the security
# component does not depend on it, PoC 1 above is what fails on the baseline.
###############################################################################
$traversalOpen = $false
try {
    $url = 'http://localhost:4848/theme/META-INF/prototype%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/domain.xml'
    $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10
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
    $resp = Invoke-WebRequest -Uri 'http://localhost:8080/' -UseBasicParsing -TimeoutSec 10
    if ($resp.StatusCode -notin 200, 302, 404) {
        $gfOk = $false
        $gfWhy = "GlassFish 8080 returned unexpected status $($resp.StatusCode)."
    }
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    if ($code -notin 200, 302, 404) {
        $gfOk = $false
        $gfWhy = "GlassFish not responding on 8080 after a ${gfWaitSec}s bounded readiness wait (ready=$gfReady): $($_.Exception.Message)"
    }
}
if ($gfOk) { Record-Reg glassfish_http_8080 1 }
else       { Record-Reg glassfish_http_8080 0 $gfWhy }

Complete-Verify
