# Verification script for Scenario 20: hidden local admin backdoor account
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

$rogue = 'support$'

###############################################################################
# PoC Check 1: the rogue account must not be a member of Administrators
###############################################################################
$members = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
foreach ($m in $members) {
    if ($m.Name -match "\\$([regex]::Escape($rogue))$" -or $m.Name -eq $rogue) {
        Write-Host "FAIL [PoC]: '$rogue' is still a member of Administrators."
        exit 1
    }
}
Write-Host "PASS [PoC]: '$rogue' not in Administrators."

###############################################################################
# PoC Check 2: the rogue account should not exist in the local SAM at all
###############################################################################
$user = Get-LocalUser -Name $rogue -ErrorAction SilentlyContinue
if ($user) {
    Write-Host "FAIL [PoC]: local user '$rogue' still exists in the SAM."
    exit 1
}
Write-Host "PASS [PoC]: local user '$rogue' removed."

###############################################################################
# PoC Check 3: no other non-built-in local account ends in '$' (RID-hiding pattern)
###############################################################################
$builtIn = @('DefaultAccount','WDAGUtilityAccount','Guest','Administrator')
$suspicious = Get-LocalUser | Where-Object {
    $_.Name -match '\$$' -and $builtIn -notcontains $_.Name
}
if ($suspicious) {
    Write-Host "FAIL [PoC]: other local accounts with '`$'-suffix still present:"
    $suspicious | ForEach-Object { Write-Host "  - $($_.Name)" }
    exit 1
}
Write-Host "PASS [PoC]: no other '`$'-suffix local accounts present."

###############################################################################
# Regression Check: the built-in Administrator group is still functional and
# contains at least one member (the vagrant account from the base image).
###############################################################################
if (-not $members -or $members.Count -lt 1) {
    Write-Host "FAIL [Regression]: Administrators group is empty or unreadable — host will be unmanageable."
    exit 1
}
Write-Host "PASS [Regression]: Administrators group still populated ($($members.Count) member(s))."

Write-Host "All checks passed."
exit 0
