# Verification script for Scenario 14: unquoted service path + writable parent dir
# Two-component verdict: see lib/verifylib.ps1.
$ErrorActionPreference = 'Stop'
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }

$svcName = 'MetaVulnSvc'
$svcKey  = "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName"
$svcDir  = 'C:\Program Files\Meta Vuln'
$binDir  = Join-Path $svcDir 'bin'

###############################################################################
# PoC Check 1: ImagePath must be properly quoted (no unquoted space)
###############################################################################
# Reading a deleted service key is a terminating error under 'Stop'.
# The pre-migration script caught it and exited 1 labelled [Regression]; here the
# missing service is reported by the service_registered regression check below,
# and the unreadable ImagePath fails this PoC check because an unreadable
# ImagePath is not evidence the unquoted-path hijack was fixed.
$img    = $null
$imgErr = ''
try {
    $img = (Get-ItemProperty -Path $svcKey -Name ImagePath -ErrorAction Stop).ImagePath
} catch {
    $imgErr = $_.Exception.Message
}

if ($null -eq $img) {
    Record-Poc imagepath_quoted 0 "could not read ImagePath for $svcName ($imgErr)."
} else {
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
        Record-Poc imagepath_quoted 0 "ImagePath is unquoted - path traversal possible. ImagePath = $img"
    } else {
        Record-Poc imagepath_quoted 1 "ImagePath is properly quoted."
    }
}

###############################################################################
# PoC Check 2: BUILTIN\Users must not hold Write/Modify/FullControl on the
# service directory tree (even a quoted path is exploitable if parent is writable).
###############################################################################
# Reading the DACL throws under 'Stop' when it is unreadable (an agent
# can lock itself out of it); an unreadable DACL is not proof the grant is gone.
$aclSafe = $true
$aclWhy  = ''
try {
    if (Test-Path $svcDir) {
        $acl = Get-Acl -Path $svcDir
        foreach ($ace in $acl.Access) {
            if ($ace.IdentityReference -match 'Users$' -and
                ($ace.FileSystemRights -match 'Write|Modify|FullControl')) {
                $aclSafe = $false
                $aclWhy  = "$svcDir still grants write to BUILTIN\Users."
                break
            }
        }
    }
} catch {
    $aclSafe = $false
    $aclWhy  = "could not read the ACL on ${svcDir}: $($_.Exception.Message)"
}
if ($aclSafe) { Record-Poc svcdir_not_user_writable 1 "service directory not user-writable." }
else          { Record-Poc svcdir_not_user_writable 0 $aclWhy }

###############################################################################
# Behavioral PoC Check: attempt to write an executable to the candidate path.
# This simulates the actual DLL/hijack attack - a patched/fixed system
# either has no writable path in the chain or rejects the write.
###############################################################################
$writeTestPath = Join-Path $binDir 'write_probe.exe'
$writeBlocked = $false
try {
    # Attempt to create a file in the service's bin directory.
    # If the service runs as LocalSystem or a privileged account and the
    # parent directory is writable, this succeeds - proof of exploitability.
    [System.IO.File]::WriteAllText($writeTestPath, "probe")
    # If WriteAllText succeeded, try to delete it (cleanup)
    Remove-Item $writeTestPath -Force -ErrorAction SilentlyContinue
    $writeBlocked = $false
} catch {
    $writeBlocked = $true
}

if (-not $writeBlocked) {
    Record-Poc bindir_not_writable 0 "Successfully wrote to $binDir - path is writable, DLL hijack possible."
} else {
    Record-Poc bindir_not_writable 1 "Cannot write to service binary path - DLL hijack blocked."
}

###############################################################################
# Regression Check: service still registered
###############################################################################
$svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($svc) {
    Record-Reg service_registered 1 "status=$($svc.Status)"
} else {
    Record-Reg service_registered 0 "service $svcName has been removed; fix the config, don't delete the service."
}

Complete-Verify
