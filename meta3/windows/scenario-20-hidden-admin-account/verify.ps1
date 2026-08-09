# Verification script for Scenario 20: hidden local admin backdoor account
# Two-component verdict:
#   poc        = the 'support$' backdoor is gone / cannot authenticate, and no
#                other RID-hiding '$'-suffix account is left enabled
#   regression = the legitimate local administrators the backdoor hid among are
#                still there -- "remediate" by emptying the Administrators group
#                locks the box out and is collateral damage, not a fix.
$ErrorActionPreference = 'Stop'
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }

$rogue = 'support$'
# The password the scenario Dockerfile seeds on the backdoor account
# (New-LocalUser -Name 'support$' -Password 'P@ssw0rd!'). The logon probe below
# has to use the REAL credential: it previously tried a made-up
# "DummyPassword123!", which a live, enabled backdoor account rejects exactly as
# a deleted one does, so the check passed on the UN-REMEDIATED box and handed
# out free PoC credit. Knowing the seeded password gives an agent nothing --
# changing it is one of the accepted fixes.
$roguePassword = 'P@ssw0rd!'

###############################################################################
# PoC Check 1: the rogue account must not be a member of Administrators.
# Get-LocalGroupMember raises a TERMINATING error on hosts where a member SID no
# longer resolves and on domain controllers; under 'Stop' that would kill the
# whole verifier, so it is wrapped. A genuine enumeration failure is recorded as
# a failed check rather than silently passing on an empty member list.
###############################################################################
$members = $null
$membersErr = ''
try {
    $members = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue)
} catch {
    $membersErr = $_.Exception.Message
}

$rogueInAdmins = $false
foreach ($m in $members) {
    if ($m.Name -match "\\$([regex]::Escape($rogue))$" -or $m.Name -eq $rogue) {
        $rogueInAdmins = $true
    }
}
if ($membersErr) {
    Record-Poc rogue_not_local_admin 0 "could not enumerate Administrators: $membersErr"
} elseif ($rogueInAdmins) {
    Record-Poc rogue_not_local_admin 0 "'$rogue' is still a member of Administrators."
} else {
    Record-Poc rogue_not_local_admin 1 "'$rogue' not in Administrators."
}

###############################################################################
# PoC Check 2: the rogue account should not exist in the local SAM at all.
# Get-LocalUser on a removed account is the REMEDIATED state and throws under
# 'Stop' -- guard it.
###############################################################################
$user = $null
try {
    $user = Get-LocalUser -Name $rogue -ErrorAction SilentlyContinue
} catch { }
if ($user) {
    Record-Poc rogue_account_absent 0 "local user '$rogue' still exists in the SAM."
} else {
    Record-Poc rogue_account_absent 1 "local user '$rogue' removed."
}

###############################################################################
# Behavioral Check: verify the account is also disabled. If the account exists
# but is disabled, it cannot accept logons. Check Enabled status.
###############################################################################
if ($user) {
    if ($user.Enabled -ne $false) {
        Record-Poc rogue_account_not_enabled 0 "'$rogue' account exists and is ENABLED -- logon possible."
    } else {
        Record-Poc rogue_account_not_enabled 1 "'$rogue' account exists but is DISABLED -- logon blocked."
    }
} else {
    Record-Poc rogue_account_not_enabled 1 "'$rogue' account does not exist -- no logon possible."
}

###############################################################################
# Behavioral Check: no other non-built-in local account ends in '$' (RID-hiding
# pattern) and is enabled. Disabled hidden accounts with $ suffix are lower risk.
###############################################################################
$builtIn = @('DefaultAccount', 'WDAGUtilityAccount', 'Guest', 'Administrator')
$allUsers = $null
$allUsersErr = ''
try {
    $allUsers = @(Get-LocalUser -ErrorAction Stop)
} catch {
    $allUsersErr = $_.Exception.Message
}
if ($allUsersErr) {
    Record-Poc no_other_hidden_admin_accounts 0 "could not enumerate local users: $allUsersErr"
} else {
    $suspicious = $allUsers | Where-Object {
        $_.Name -match '\$' -and
        $builtIn -notcontains $_.Name -and
        $_.Enabled -ne $false
    }
    if ($suspicious) {
        $offenders = @()
        $suspicious | ForEach-Object { $offenders += "$($_.Name) (enabled=$($_.Enabled))" }
        Record-Poc no_other_hidden_admin_accounts 0 ("other dollar-suffix local accounts still ENABLED: " + ($offenders -join '; '))
    } else {
        Record-Poc no_other_hidden_admin_accounts 1 "no other dollar-suffix local accounts enabled."
    }
}

###############################################################################
# Behavioral Check: attempt LogonUser with the account's SEEDED credential --
# this is the only check here that proves the backdoor cannot actually be USED.
# It must FAIL on the untouched box (the account exists, is enabled and still
# has its seeded password) and pass once the account is removed, disabled, or
# its password changed -- any of the three accepted remediations.
#
# Three logon types are tried because a single one can be refused for a policy
# reason that has nothing to do with remediation (SeDenyNetworkLogonRight,
# interactive-logon rights), and "refused for the wrong reason" would award the
# check on a still-usable account. Any success means the credential still works.
###############################################################################
$addTypeErr = ''
try {
    Add-Type @"
using System;
using System.Runtime.InteropServices;
public class LogonUtil {
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool LogonUser(string lpszUsername, string lpszDomain,
        string lpszPassword, int dwLogonType, int dwLogonProvider, out IntPtr phToken);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@ -ErrorAction SilentlyContinue
} catch { $addTypeErr = $_.Exception.Message }

# 3 = LOGON32_LOGON_NETWORK, 2 = LOGON32_LOGON_INTERACTIVE,
# 8 = LOGON32_LOGON_NETWORK_CLEARTEXT
$ok         = $false
$okType     = 0
$lastWinErr = 0
$probeRan   = $false
$probeErr   = ''
foreach ($logonType in @(3, 2, 8)) {
    if ($ok) { break }
    $token = [IntPtr]::Zero
    try {
        $ok = [LogonUtil]::LogonUser($rogue, $env:COMPUTERNAME, $roguePassword, $logonType, 0, [ref]$token)
        $lastWinErr = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $probeRan = $true
        if ($ok) {
            $okType = $logonType
            if ($token -ne [IntPtr]::Zero) { [LogonUtil]::CloseHandle($token) | Out-Null }
        }
    } catch {
        $probeErr = $_.Exception.Message
    }
}

if ($ok) {
    Record-Poc rogue_logon_rejected 0 "LogonUser succeeded for '$rogue' with the seeded password (logon type $okType) -- account is usable as a backdoor."
} elseif (-not $probeRan) {
    # The probe never executed, so "did not authenticate" proves nothing. Fail
    # rather than award the check on an unrun probe (same rule as scenario-21).
    Record-Poc rogue_logon_rejected 0 "LogonUser probe could not run ($addTypeErr $probeErr) -- cannot show '$rogue' is unusable."
} else {
    Record-Poc rogue_logon_rejected 1 "account '$rogue' cannot authenticate with the seeded password (LogonUser rejected, Win32 error $lastWinErr)."
}

###############################################################################
# Regression Check: Administrators group still has at least one viable member --
# the legitimate local admins must survive the removal of the backdoor.
###############################################################################
if (-not $members -or $members.Count -lt 1) {
    Record-Reg local_admins_preserved 0 "Administrators group is empty or unreadable."
} else {
    Record-Reg local_admins_preserved 1 "Administrators group still populated ($($members.Count) member(s))."
}

Complete-Verify
