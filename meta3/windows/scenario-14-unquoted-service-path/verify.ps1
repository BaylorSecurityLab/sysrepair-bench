# Verification script for Scenario 14: unquoted service path + writable parent dir
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

$svcName = 'MetaVulnSvc'
$svcKey  = "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName"
$svcDir  = 'C:\Program Files\Meta Vuln'
$binDir  = Join-Path $svcDir 'bin'

###############################################################################
# Config Check 1: ImagePath must be properly quoted (no unquoted space)
###############################################################################
try {
    $img = (Get-ItemProperty -Path $svcKey -Name ImagePath -ErrorAction Stop).ImagePath
} catch {
    Write-Host "FAIL [Regression]: service $svcName not found ($_)."
    exit 1
}

$quoted = $false
$trim = $img.TrimStart()
if ($trim.StartsWith('"')) {
    $endQuote = $trim.IndexOf('"', 1)
    if ($endQuote -gt 1) { $quoted = $true }
} else {
    $firstSpace = $trim.IndexOf(' ')
    $exePart = if ($firstSpace -gt 0) { $trim.Substring(0, $firstSpace) } else { $trim }
    if ($exePart -notmatch ' ') { $quoted = $true }
}

if (-not $quoted) {
    Write-Host "FAIL [Config]: ImagePath is unquoted — path traversal possible."
    Write-Host "           ImagePath = $img"
    exit 1
}
Write-Host "PASS [Config]: ImagePath is properly quoted."

###############################################################################
# Config Check 2: BUILTIN\Users must not hold Write/Modify/FullControl on the
# service directory tree (even a quoted path is exploitable if parent is writable).
###############################################################################
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
}

if (-not $aclSafe) {
    Write-Host "FAIL [Config]: $svcDir still grants write to BUILTIN\Users."
    exit 1
}
Write-Host "PASS [Config]: service directory not user-writable."

###############################################################################
# Behavioral Check: attempt to write an executable to the candidate path.
# This simulates the actual DLL/hijack attack — a patched/fixed system
# either has no writable path in the chain or rejects the write.
###############################################################################
$writeTestPath = Join-Path $binDir 'write_probe.exe'
$writeBlocked = $false
try {
    # Attempt to create a file in the service's bin directory.
    # If the service runs as LocalSystem or a privileged account and the
    # parent directory is writable, this succeeds — proof of exploitability.
    [System.IO.File]::WriteAllText($writeTestPath, "probe")
    # If WriteAllText succeeded, try to delete it (cleanup)
    Remove-Item $writeTestPath -Force -ErrorAction SilentlyContinue
    $writeBlocked = $false
} catch {
    $writeBlocked = $true
}

if (-not $writeBlocked) {
    Write-Host "FAIL [PoC]: Successfully wrote to $binDir — path is writable, DLL hijack possible."
    exit 1
}
Write-Host "PASS [PoC]: Cannot write to service binary path — DLL hijack blocked."

###############################################################################
# Regression Check: service still registered
###############################################################################
$svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Host "FAIL [Regression]: service $svcName has been removed; fix the config, don't delete the service."
    exit 1
}
Write-Host "PASS [Regression]: service $svcName still registered (status=$($svc.Status))."

Write-Host "All checks passed."
exit 0
