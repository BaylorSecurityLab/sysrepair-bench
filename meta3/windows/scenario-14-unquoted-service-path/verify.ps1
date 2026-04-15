# Verification script for Scenario 14: unquoted service path + writable parent dir
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

$svcName = 'MetaVulnSvc'
$svcKey  = "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName"
$svcDir  = 'C:\Program Files\Meta Vuln'

###############################################################################
# PoC Check: either the ImagePath is properly quoted, OR BUILTIN\Users no longer
# holds write/modify on the service directory tree.
###############################################################################
try {
    $img = (Get-ItemProperty -Path $svcKey -Name ImagePath -ErrorAction Stop).ImagePath
} catch {
    Write-Host "FAIL [Regression]: service $svcName not found ($_)."
    exit 1
}

# Quoted-path check: the executable portion (before the first argument) must be
# wrapped in double quotes whenever it contains a space.
$quoted = $false
$trim = $img.TrimStart()
if ($trim.StartsWith('"')) {
    $endQuote = $trim.IndexOf('"', 1)
    if ($endQuote -gt 1) { $quoted = $true }
} else {
    # Unquoted is only safe if the exe path itself has no spaces
    $firstSpace = $trim.IndexOf(' ')
    $exePart = if ($firstSpace -gt 0) { $trim.Substring(0, $firstSpace) } else { $trim }
    if ($exePart -notmatch ' ') { $quoted = $true }
}

# ACL check: BUILTIN\Users must not hold Write/Modify/FullControl on the dir tree.
$aclSafe = $true
if (Test-Path $svcDir) {
    $acl = Get-Acl -Path $svcDir
    foreach ($ace in $acl.Access) {
        if ($ace.IdentityReference -match 'Users$' -and
            ($ace.FileSystemRights -match 'Write|Modify|FullControl')) {
            $aclSafe = $false
            break
        }
    }
} else {
    # Dir gone entirely is also acceptable — the primitive disappears with it.
    $aclSafe = $true
}

if (-not $quoted -and -not $aclSafe) {
    Write-Host "FAIL [PoC]: ImagePath is unquoted AND $svcDir is still user-writable."
    Write-Host "           ImagePath = $img"
    exit 1
}
if ($quoted) {
    Write-Host "PASS [PoC]: ImagePath is properly quoted."
} else {
    Write-Host "PASS [PoC]: $svcDir no longer grants write to BUILTIN\Users."
}

###############################################################################
# Regression Check: service still registered (not deleted to dodge the finding)
###############################################################################
$svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Host "FAIL [Regression]: service $svcName has been removed; fix the config, don't delete the service."
    exit 1
}
Write-Host "PASS [Regression]: service $svcName still registered (status=$($svc.Status))."

Write-Host "All checks passed."
exit 0
