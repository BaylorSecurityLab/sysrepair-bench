# Verification script for Scenario 03: IIS FTP anonymous read+write
# Two-component verdict: see lib/verifylib.ps1.
$ErrorActionPreference = 'Stop'
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }

###############################################################################
# Regression Check: ftpsvc running and listening on 21
###############################################################################
$svc = Get-Service -Name ftpsvc -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Record-Reg ftpsvc_running 1
} else {
    Record-Reg ftpsvc_running 0 "ftpsvc is not running (status='$($svc.Status)')."
}

$listening = Get-NetTCPConnection -LocalPort 21 -State Listen -ErrorAction SilentlyContinue
if ($listening) { Record-Reg tcp21_bound 1 }
else            { Record-Reg tcp21_bound 0 "Nothing listening on TCP/21." }

###############################################################################
# PoC Check 1: anonymous FTP download must be blocked
# Functional test - try downloading a known file as anonymous.
###############################################################################
$anonOk = $false
try {
    $req = [System.Net.WebRequest]::Create('ftp://localhost/README.txt')
    $req.Method = 'RETR'
    $req.Credentials = [System.Net.NetworkCredential]::new('anonymous', 'test@test.com')
    $req.Timeout = 10000
    $resp = $req.GetResponse()
    $resp.Close()
    $anonOk = $true
} catch {
    # Connection refused, 530 auth failure, or SSL-required all count as blocked
}

if ($anonOk) {
    Record-Poc anon_download_blocked 0 "Anonymous FTP download succeeded - anonymous access is still open."
} else {
    Record-Poc anon_download_blocked 1
}

###############################################################################
# PoC Check 2: no authorization rule granting anonymous ('?') any access
###############################################################################
Import-Module WebAdministration -ErrorAction SilentlyContinue
# Under 'Stop' this throws if WebAdministration did not load (the cmdlet then
# does not exist) or if the MetaFTP location was removed - both are states an
# agent can leave behind, and an unreadable ruleset cannot prove the anonymous
# grant is gone.
try {
    $rules = Get-WebConfiguration -Filter '/system.ftpServer/security/authorization/add' `
        -PSPath 'MACHINE/WEBROOT/APPHOST' -Location 'MetaFTP' -ErrorAction SilentlyContinue
    $anonRule = $rules | Where-Object { $_.users -eq '?' -and $_.accessType -eq 'Allow' }
    if ($anonRule) {
        Record-Poc no_anon_allow_rule 0 "Authorization rule still grants anonymous user access (permissions='$($anonRule.permissions)')."
    } else {
        Record-Poc no_anon_allow_rule 1
    }
} catch {
    Record-Poc no_anon_allow_rule 0 "could not read FTP authorization rules: $($_.Exception.Message)"
}

Complete-Verify
