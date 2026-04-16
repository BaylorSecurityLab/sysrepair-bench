# Verification script for Scenario 21: OpenSSH-Win32 legacy build + vagrant:vagrant defaults
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

###############################################################################
# PoC Check 1: vagrant:vagrant must no longer authenticate. We assert either
#   - the vagrant account does not exist / is not in Administrators, OR
#   - its password is no longer 'vagrant' (tested via Test-ComputerSecureChannel-
#     style local logon using LogonUser P/Invoke).
###############################################################################
$vagrantUnsafe = $true
$user = Get-LocalUser -Name 'vagrant' -ErrorAction SilentlyContinue
if (-not $user) {
    $vagrantUnsafe = $false
    Write-Host "PASS [PoC]: vagrant account removed."
} else {
    $inAdmins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match '\\vagrant$' -or $_.Name -eq 'vagrant'
    }
    if (-not $inAdmins) {
        $vagrantUnsafe = $false
        Write-Host "PASS [PoC]: vagrant account no longer in Administrators."
    } else {
        # Try the default password via Win32 LogonUser
        Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError=true)]
public static extern bool LogonUser(string user, string domain, string pass,
    int logonType, int logonProvider, out System.IntPtr token);
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
public static extern bool CloseHandle(System.IntPtr h);
'@
        $token = [IntPtr]::Zero
        $ok = [Win32.NativeMethods]::LogonUser('vagrant', '.', 'vagrant', 2, 0, [ref]$token)
        if ($ok) {
            [Win32.NativeMethods]::CloseHandle($token) | Out-Null
            Write-Host "FAIL [PoC]: vagrant:vagrant still authenticates locally."
            exit 1
        }
        $vagrantUnsafe = $false
        Write-Host "PASS [PoC]: vagrant default password no longer valid."
    }
}

###############################################################################
# PoC Check 2: the legacy Win32-OpenSSH binary must be replaced. Accept either
#   - the capability-installed sshd (under C:\Windows\System32\OpenSSH\), OR
#   - a Win32-OpenSSH release with ProductVersion >= 9.0.
###############################################################################
$sshdCap = 'C:\Windows\System32\OpenSSH\sshd.exe'
$sshdLeg = 'C:\Program Files\OpenSSH\sshd.exe'

$binFixed = $false
if (Test-Path $sshdCap) {
    $v = (Get-Item $sshdCap).VersionInfo.ProductVersion
    Write-Host "INFO [PoC]: capability sshd.exe present, version $v."
    $binFixed = $true
}
if (-not $binFixed -and (Test-Path $sshdLeg)) {
    $v = (Get-Item $sshdLeg).VersionInfo.ProductVersion
    if ($v -match '^(\d+)\.') {
        $major = [int]$matches[1]
        if ($major -ge 9) {
            Write-Host "INFO [PoC]: legacy-path sshd.exe upgraded to $v."
            $binFixed = $true
        }
    }
    if (-not $binFixed) {
        Write-Host "FAIL [PoC]: legacy Win32-OpenSSH still at $v (needs replacement or upgrade to 9.x+)."
        exit 1
    }
}
if (-not $binFixed) {
    Write-Host "FAIL [PoC]: no recognizable sshd.exe found; SSH has been removed rather than upgraded."
    exit 1
}
Write-Host "PASS [PoC]: sshd binary is on a supported OpenSSH build."

###############################################################################
# Regression Check: sshd service still running and 22/TCP listening
###############################################################################
$svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') {
    Write-Host "FAIL [Regression]: sshd service is not running."
    exit 1
}
$listen = Get-NetTCPConnection -LocalPort 22 -State Listen -ErrorAction SilentlyContinue
if (-not $listen) {
    Write-Host "FAIL [Regression]: nothing listening on TCP/22."
    exit 1
}
Write-Host "PASS [Regression]: sshd running and 22/TCP listening."

Write-Host "All checks passed."
exit 0
