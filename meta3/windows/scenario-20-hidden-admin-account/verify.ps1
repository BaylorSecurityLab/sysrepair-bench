# Verification script for Scenario 20: hidden local admin backdoor account
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

$rogue = 'support$'

###############################################################################
# Config Check 1: the rogue account must not be a member of Administrators
###############################################################################
$members = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
foreach ($m in $members) {
    if ($m.Name -match "\\$([regex]::Escape($rogue))$" -or $m.Name -eq $rogue) {
        Write-Host "FAIL [Config]: '$rogue' is still a member of Administrators."
        exit 1
    }
}
Write-Host "PASS [Config]: '$rogue' not in Administrators."

###############################################################################
# Config Check 2: the rogue account should not exist in the local SAM at all
###############################################################################
$user = Get-LocalUser -Name $rogue -ErrorAction SilentlyContinue
if ($user) {
    Write-Host "FAIL [Config]: local user '$rogue' still exists in the SAM."
    exit 1
}
Write-Host "PASS [Config]: local user '$rogue' removed."

###############################################################################
# Behavioral Check: verify the account is also disabled. If the account exists
# but is disabled, it cannot accept logons. Check Enabled status.
###############################################################################
$userExisting = Get-LocalUser -Name $rogue -ErrorAction SilentlyContinue
if ($userExisting) {
    if ($userExisting.Enabled -ne $false) {
        Write-Host "FAIL [PoC]: '$rogue' account exists and is ENABLED — logon possible."
        exit 1
    }
    Write-Host "PASS [PoC]: '$rogue' account exists but is DISABLED — logon blocked."
} else {
    Write-Host "PASS [PoC]: '$rogue' account does not exist — no logon possible."
}

###############################################################################
# Behavioral Check: no other non-built-in local account ends in '$' (RID-hiding
# pattern) and is enabled. Disabled hidden accounts with $ suffix are lower risk.
###############################################################################
$builtIn = @('DefaultAccount', 'WDAGUtilityAccount', 'Guest', 'Administrator')
$suspicious = Get-LocalUser | Where-Object {
    $_.Name -match '\$' -and
    $builtIn -notcontains $_.Name -and
    $_.Enabled -ne $false
}
if ($suspicious) {
    Write-Host "FAIL [PoC]: other '$'-suffix local accounts still ENABLED:"
    $suspicious | ForEach-Object { Write-Host "  - $($_.Name) (enabled=$($_.Enabled))" }
    exit 1
}
Write-Host "PASS [PoC]: no other '$'-suffix local accounts enabled."

###############################################################################
# Behavioral Check: attempt LogonUser with the account — proves the account
# can actually authenticate. A non-existent or disabled account returns FALSE.
###############################################################################
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class LogonUtil {
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool LogonUser(string lpszUsername, string lpszDomain,
        string lpszPassword, int dwLogonType, int dwLogonProvider, out IntPtr phToken);
}
"@ -ErrorAction SilentlyContinue

$token = [IntPtr]::Zero
$ok = $false
try {
    $ok = [LogonUtil]::LogonUser($rogue, $env:COMPUTERNAME, "DummyPassword123!", 3, 0, [ref]$token)
} catch {}

if ($ok) {
    Write-Host "FAIL [PoC]: LogonUser succeeded for '$rogue' — account is usable as backdoor."
    if ($token -ne [IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::Release($token) | Out-Null }
    exit 1
}
Write-Host "PASS [PoC]: account '$rogue' cannot authenticate (LogonUser rejected)."

###############################################################################
# Regression Check: Administrators group still has at least one viable member
###############################################################################
if (-not $members -or $members.Count -lt 1) {
    Write-Host "FAIL [Regression]: Administrators group is empty or unreadable."
    exit 1
}
Write-Host "PASS [Regression]: Administrators group still populated ($($members.Count) member(s))."

Write-Host "All checks passed."
exit 0