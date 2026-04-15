# Verification script for Scenario 03: IIS FTP anonymous read+write
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'
Import-Module WebAdministration -ErrorAction SilentlyContinue

$site = 'IIS:\Sites\MetaFTP'

###############################################################################
# PoC Check 1: anonymous authentication must be disabled
###############################################################################
$anon = (Get-WebConfigurationProperty -Filter '/system.ftpServer/security/authentication/anonymousAuthentication' `
    -PSPath $site -Name enabled).Value
if ($anon -eq $true) {
    Write-Host "FAIL [PoC]: Anonymous FTP authentication is still enabled."
    exit 1
}
Write-Host "PASS [PoC]: Anonymous FTP authentication disabled."

###############################################################################
# PoC Check 2: no authorization rule granting anonymous ('?') any access
###############################################################################
$rules = Get-WebConfiguration -Filter '/system.ftpServer/security/authorization/add' -PSPath $site
$anonRule = $rules | Where-Object { $_.users -eq '?' -and $_.accessType -eq 'Allow' }
if ($anonRule) {
    Write-Host "FAIL [PoC]: Authorization rule still grants anonymous user access (permissions='$($anonRule.permissions)')."
    exit 1
}
Write-Host "PASS [PoC]: No anonymous allow rule."

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

Write-Host "All checks passed."
exit 0
