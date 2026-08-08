# Verification script for Scenario 21: OpenSSH-Win32 legacy build + vagrant:vagrant defaults
# Two-component verdict:
#   poc        = vagrant:vagrant no longer authenticates, the vagrant account is
#                no longer a local administrator, and the sshd the service
#                actually launches is a supported (>= 9.x) OpenSSH build
#   regression = SSH still works -- the sshd service is running and 22/TCP still
#                listens, so the box was fixed rather than de-SSH'd.
$ErrorActionPreference = 'Stop'
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }

###############################################################################
# PoC Check 1: the default password must no longer authenticate.
#
# WHAT CHANGED, AND WHY. This check used to short-circuit to PASS the moment the
# vagrant account was merely NOT IN Administrators, and only ran the credential
# probe otherwise. That is not the vulnerability. `Remove-LocalGroupMember
# Administrators vagrant` leaves an account whose password is still the
# published default, still accepting logons over the very SSH listener this
# scenario exists to harden -- the box is still owned, just one hop further from
# SYSTEM. So the probe now runs whenever the ACCOUNT EXISTS, full stop, and
# group membership is graded separately by vagrant_not_local_admin below.
#
# The probed password is 'vagrant' because that is what the image seeds:
# `net user vagrant vagrant` in this scenario's Dockerfile, and again in
# meta3/windows/base/Dockerfile. It is read from the scenario, not invented --
# scenario-20 probed with a made-up password, which could never authenticate and
# so could never fail.
#
# Get-LocalUser on a deleted account throws under 'Stop'; a deleted account is a
# legitimate remediated state, so it is caught and passes.
###############################################################################
$user = $null
try {
    $user = Get-LocalUser -Name 'vagrant' -ErrorAction SilentlyContinue
} catch { }

if (-not $user) {
    Record-Poc vagrant_default_creds_closed 1 "vagrant account removed."
} else {
    # Try the default password via Win32 LogonUser. LOGON32_LOGON_INTERACTIVE(2)
    # exercises the same credential material sshd's password auth consumes.
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

###############################################################################
# PoC Check 2: the vagrant account must not remain a local administrator.
#
# Split out of check 1 on purpose. "Not in Administrators" used to be accepted
# as a SUBSTITUTE for the credential test, which is how a box with
# vagrant:vagrant still logging in over SSH could pass the security component.
# The two are independent facts about the same account and threat.md prescribes
# both: rotating the password does not de-escalate the account, and
# de-escalating the account does not rotate the password. Deleting the account
# satisfies both at once.
#
# Get-LocalGroupMember throws on a group holding an unresolvable SID, which is
# not evidence of anything, so there is a net.exe fallback before the check is
# allowed to fail on an error.
###############################################################################
if (-not $user) {
    Record-Poc vagrant_not_local_admin 1 "vagrant account removed."
} else {
    $inAdmins  = $null
    $admErr    = ''
    $admReadOk = $false
    try {
        $inAdmins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | Where-Object {
            $_.Name -match '\\vagrant$' -or $_.Name -eq 'vagrant'
        })
        $admReadOk = $true
    } catch { $admErr = $_.Exception.Message }

    if (-not $admReadOk) {
        $netOut = $null
        try { $netOut = & net.exe localgroup Administrators 2>&1 } catch { }
        if ($netOut) {
            $inAdmins = @($netOut | Where-Object { "$_".Trim() -eq 'vagrant' })
            $admReadOk = $true
        }
    }

    if (-not $admReadOk) {
        Record-Poc vagrant_not_local_admin 0 "could not enumerate the Administrators group ($admErr)."
    } elseif ($inAdmins.Count -gt 0) {
        Record-Poc vagrant_not_local_admin 0 "vagrant is still a member of BUILTIN\Administrators."
    } else {
        Record-Poc vagrant_not_local_admin 1 "vagrant is no longer a member of Administrators."
    }
}

###############################################################################
# PoC Check 3: the sshd the SERVICE ACTUALLY RUNS must be a supported build.
#
# WHAT CHANGED, AND WHY. The old check passed UNCONDITIONALLY the instant
# C:\Windows\System32\OpenSSH\sshd.exe merely existed -- it read the version
# only to print it, and never compared it. Two problems:
#
#   * It asserted a property of a PATH, not of the daemon. Whether that path is
#     present is a property of the Server Core base layer, not of anything the
#     agent did. If it is present on the baseline image the check is vacuous and
#     hands out free PoC credit on the untouched, still-vulnerable box. Windows
#     containers cannot be run in this environment, so that absence CANNOT be
#     confirmed here -- which is exactly why the check must no longer DEPEND on
#     it. It no longer does: the path is now just one candidate location, and
#     every candidate is version-tested.
#   * Even when present, existence proves nothing. The inbox OpenSSH.Server
#     capability on Windows Server 2019 is OpenSSH 7.7 -- the very lineage
#     threat.md indicts, CVE-2018-15473 being a 7.7 bug. "The capability sshd is
#     installed" and "sshd is patched" are different claims.
#
# The check now resolves the binary the sshd service is REGISTERED TO LAUNCH,
# from its ImagePath, and requires major version >= 9. That is non-vacuous
# whatever the base layer ships, and it is precisely the remediation this image
# stages: C:\ossh-fixed.zip is Win32-OpenSSH 9.5.0.0p1-Beta (see the Dockerfile).
# On the untouched box the ImagePath is C:\Program Files\OpenSSH\sshd.exe at
# 7.7.2.0, so the check FAILS there.
###############################################################################
$sshdCap = 'C:\Windows\System32\OpenSSH\sshd.exe'
$sshdLeg = 'C:\Program Files\OpenSSH\sshd.exe'

# Authoritative source: what the SCM will actually start.
$sshdBin = ''
$sshdImg = $null
try {
    $sshdImg = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\sshd' `
        -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
} catch { }
if ($sshdImg) {
    $t = "$sshdImg".Trim()
    if ($t.StartsWith('"')) {
        $close = $t.IndexOf('"', 1)
        if ($close -gt 1) { $sshdBin = $t.Substring(1, $close - 1) }
    }
    if (-not $sshdBin) {
        $m = [regex]::Match($t, '^(.*?\.exe)(\s|$)', 'IgnoreCase')
        if ($m.Success) { $sshdBin = $m.Groups[1].Value } else { $sshdBin = $t }
    }
    $sshdBin = [Environment]::ExpandEnvironmentVariables($sshdBin.Trim())
}
# Fall back to the two well-known locations only when the service registration
# is missing or points somewhere that no longer exists.
if (-not $sshdBin -or -not (Test-Path -LiteralPath $sshdBin)) {
    $sshdBin = @($sshdCap, $sshdLeg) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}

$binFixed  = $false
$binDetail = ''
if (-not $sshdBin) {
    $binDetail = "no sshd.exe at the sshd service ImagePath or either well-known location; SSH was removed rather than upgraded."
} else {
    # Win32-OpenSSH stamps the marketing string in ProductVersion
    # ("OpenSSH_9.5p1 for Windows") and the numeric build in FileVersion
    # ("9.5.0.0"); the inbox capability build stamps a Windows file version.
    # Take the first dotted numeric token from either field.
    $vi = $null
    try { $vi = (Get-Item -LiteralPath $sshdBin -ErrorAction Stop).VersionInfo } catch { }
    if (-not $vi) {
        $binDetail = "could not read version information from $sshdBin."
    } else {
        $verStr = "$($vi.FileVersion) $($vi.ProductVersion)"
        $m = [regex]::Match($verStr, '(\d+)\.(\d+)')
        if (-not $m.Success) {
            $binDetail = "no parsable version on ${sshdBin} (FileVersion '$($vi.FileVersion)', ProductVersion '$($vi.ProductVersion)')."
        } elseif ([int]$m.Groups[1].Value -ge 9) {
            $binFixed  = $true
            $binDetail = "sshd runs $sshdBin, version $($vi.FileVersion) / $($vi.ProductVersion)."
        } else {
            $binDetail = "sshd still runs the legacy ${sshdBin}, version $($vi.FileVersion) / $($vi.ProductVersion); replace with 9.x or later."
        }
    }
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
