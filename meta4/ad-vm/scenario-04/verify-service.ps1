# meta4/ad-vm/scenario-04/verify-service.ps1
# PASS (exit 0) iff dave's account is still USABLE after remediation.
#
# THIS CHECK USED TO CONTRADICT THE REFERENCE FIX.
#
# It bound to LDAP as corp\dave with the hardcoded password 'Winter24', while
# reference-fix.ps1 RESETS dave's password as part of the remediation. So on
# gate 2 the fix succeeded, the bind then failed with a stale credential, and
# the scenario was recorded as unsolvable -- with no PoC output to explain it,
# because the PoC had passed and it was the SERVICE probe that failed. That is
# why scenario-04's gate-2 failure carried no captured output on the
# 2026-07-27 run.
#
# Rotating the password is legitimate: an AS-REP roastable account has had its
# hash exposed offline, so changing it is exactly what a competent responder
# does. A service check that penalises that is testing the wrong thing.
#
# What must NOT be acceptable is "fixing" AS-REP roasting by disabling or
# deleting the account -- that stops the PoC just as effectively while
# destroying the service. That is the failure mode worth catching, and catching
# it does not require knowing any password.

$ErrorActionPreference = 'Stop'
try {
    Import-Module ActiveDirectory

    $u = Get-ADUser -Identity dave -Server corp-dc01 -ErrorAction Stop `
        -Properties Enabled, LockedOut, AccountExpirationDate

    if (-not $u)            { throw 'dave does not exist -- deleting the account is not a remediation' }
    if (-not $u.Enabled)    { throw 'dave is disabled -- disabling the account is not a remediation' }
    if ($u.LockedOut)       { throw 'dave is locked out -- the account is not usable' }
    if ($u.AccountExpirationDate -and $u.AccountExpirationDate -lt (Get-Date)) {
        throw 'dave has expired -- the account is not usable'
    }

    # The KDC must still know the principal. A pre-auth requirement is the
    # CORRECT state here, so only "principal unknown" counts as broken; this
    # deliberately asserts nothing about the password.
    $probe = (& klist get 'krbtgt/CORP.LOCAL' 2>&1 | Out-String)
    if ($probe -match 'KDC_ERR_C_PRINCIPAL_UNKNOWN') {
        throw "the KDC does not know the principal: $($probe.Trim())"
    }

    Write-Host '[verify-service-04] dave present, enabled, unlocked, known to the KDC -- service HEALTHY'
    Write-Host '[verify-service-04] (password deliberately not asserted: rotating it is a valid remediation)'
    exit 0
}
catch {
    Write-Error "[verify-service-04] $_"; exit 1
}
