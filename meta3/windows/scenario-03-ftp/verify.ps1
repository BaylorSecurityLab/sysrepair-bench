# Verification script for Scenario 03: IIS FTP anonymous read+write
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

###############################################################################
# Regression Check: ftpsvc running and listening on 21
###############################################################################
$svc = Get-Service -Name ftpsvc -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') {
    Write-Host "FAIL [Regression]: ftpsvc is not running (status='$($svc.Status)')."
    exit 1
}
Write-Host "PASS [Regression]: ftpsvc running."

$listening = Get-NetTCPConnection -LocalPort 21 -State Listen -ErrorAction SilentlyContinue
if (-not $listening) {
    Write-Host "FAIL [Regression]: Nothing listening on TCP/21."
    exit 1
}
Write-Host "PASS [Regression]: TCP/21 bound."

###############################################################################
# PoC Check 1: anonymous FTP download must be blocked
# Functional test — try downloading a known file as anonymous.
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
    Write-Host "FAIL [PoC]: Anonymous FTP download succeeded — anonymous access is still open."
    exit 1
}
Write-Host "PASS [PoC]: Anonymous FTP download blocked."

###############################################################################
# PoC Check 2: no authorization rule granting anonymous ('?') any access
###############################################################################
Import-Module WebAdministration -ErrorAction SilentlyContinue
$rules = Get-WebConfiguration -Filter '/system.ftpServer/security/authorization/add' `
    -PSPath 'MACHINE/WEBROOT/APPHOST' -Location 'MetaFTP' -ErrorAction SilentlyContinue
$anonRule = $rules | Where-Object { $_.users -eq '?' -and $_.accessType -eq 'Allow' }
if ($anonRule) {
    Write-Host "FAIL [PoC]: Authorization rule still grants anonymous user access (permissions='$($anonRule.permissions)')."
    exit 1
}
Write-Host "PASS [PoC]: No anonymous allow rule."

Write-Host "All checks passed."
exit 0
