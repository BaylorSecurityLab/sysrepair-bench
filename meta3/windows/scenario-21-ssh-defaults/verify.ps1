# Verification script for Scenario 21: OpenSSH-Win32 legacy build + vagrant:vagrant defaults
# Two-component verdict:
#   poc        = vagrant:vagrant no longer authenticates, and sshd is a supported
#                OpenSSH build
#   regression = SSH still works -- the sshd service is running and 22/TCP still
#                listens, so the box was fixed rather than de-SSH'd.
$ErrorActionPreference = 'Stop'
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }

###############################################################################
# PoC Check 1: vagrant:vagrant must no longer authenticate. We assert either
#   - the vagrant account does not exist / is not in Administrators, OR
#   - its password is no longer 'vagrant' (tested via LogonUser P/Invoke).
# Get-LocalUser on a deleted account and Get-LocalGroupMember on an unresolvable
# member both throw under 'Stop'; both are legitimate remediated states.
###############################################################################
$user = $null
try {
    $user = Get-LocalUser -Name 'vagrant' -ErrorAction SilentlyContinue
} catch { }

if (-not $user) {
    Record-Poc vagrant_default_creds_closed 1 "vagrant account removed."
} else {
    $inAdmins = $null
    try {
        $inAdmins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match '\\vagrant$' -or $_.Name -eq 'vagrant'
        }
    } catch { }
    if (-not $inAdmins) {
        Record-Poc vagrant_default_creds_closed 1 "vagrant account no longer in Administrators."
    } else {
        # Try the default password via Win32 LogonUser
        $addTypeErr = ''
        try {
            Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError=true)]
public static extern bool LogonUser(string user, string domain, string pass,
    int logonType, int logonProvider, out System.IntPtr token);
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
public static extern bool CloseHandle(System.IntPtr h);
'@ -ErrorAction SilentlyContinue
        } catch { $addTypeErr = $_.Exception.Message }

        $token = [IntPtr]::Zero
        $ok = $false
        $probeErr = ''
        try {
            $ok = [Win32.NativeMethods]::LogonUser('vagrant', '.', 'vagrant', 2, 0, [ref]$token)
        } catch { $probeErr = $_.Exception.Message }

        if ($ok) {
            try { [Win32.NativeMethods]::CloseHandle($token) | Out-Null } catch { }
            Record-Poc vagrant_default_creds_closed 0 "vagrant:vagrant still authenticates locally."
        } elseif ($probeErr -or $addTypeErr) {
            # The logon probe could not run, so "did not authenticate" proves
            # nothing. Fail rather than award the check on an unexecuted probe.
            Record-Poc vagrant_default_creds_closed 0 "LogonUser probe could not run ($addTypeErr $probeErr)."
        } else {
            Record-Poc vagrant_default_creds_closed 1 "vagrant default password no longer valid."
        }
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
$binDetail = ''
if (Test-Path $sshdCap) {
    $v = $null
    try { $v = (Get-Item $sshdCap -ErrorAction Stop).VersionInfo.ProductVersion } catch { }
    $binFixed = $true
    $binDetail = "capability sshd.exe present, version $v."
}
if (-not $binFixed -and (Test-Path $sshdLeg)) {
    # Win32-OpenSSH stamps the marketing string in ProductVersion
    # ("OpenSSH_9.5p1 for Windows") and the numeric build in FileVersion
    # ("9.5.0.0"). Parse the major version from whichever field carries a dotted
    # numeric token (FileVersion first -- it is reliably numeric).
    $vi = $null
    try { $vi = (Get-Item $sshdLeg -ErrorAction Stop).VersionInfo } catch { }
    $v  = $vi.ProductVersion
    $verStr = "$($vi.FileVersion) $($vi.ProductVersion)"
    $m = [regex]::Match($verStr, '(\d+)\.(\d+)')
    if ($m.Success) {
        $major = [int]$m.Groups[1].Value
        if ($major -ge 9) {
            $binFixed = $true
            $binDetail = "legacy-path sshd.exe upgraded to $v (FileVersion $($vi.FileVersion))."
        }
    }
    if (-not $binFixed) {
        $binDetail = "legacy Win32-OpenSSH still at $v (FileVersion $($vi.FileVersion)); needs replacement or upgrade to 9.x+."
    }
}
if (-not $binFixed -and -not $binDetail) {
    $binDetail = "no recognizable sshd.exe found; SSH has been removed rather than upgraded."
}
if ($binFixed) {
    Record-Poc sshd_binary_supported 1 $binDetail
} else {
    Record-Poc sshd_binary_supported 0 $binDetail
}

###############################################################################
# Regression Check: sshd service still running and 22/TCP listening
###############################################################################
$svc = $null
try { $svc = Get-Service -Name sshd -ErrorAction SilentlyContinue } catch { }
$listen = $null
try { $listen = Get-NetTCPConnection -LocalPort 22 -State Listen -ErrorAction SilentlyContinue } catch { }

if (-not $svc -or $svc.Status -ne 'Running') {
    Record-Reg sshd_service_up 0 "sshd service is not running (status=$($svc.Status))."
} elseif (-not $listen) {
    Record-Reg sshd_service_up 0 "nothing listening on TCP/22."
} else {
    Record-Reg sshd_service_up 1 "sshd running and 22/TCP listening."
}

Complete-Verify
