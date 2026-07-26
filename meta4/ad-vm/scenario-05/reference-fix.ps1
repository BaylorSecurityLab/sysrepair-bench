# meta4/ad-vm/scenario-05/reference-fix.ps1
# Reference remediation for unconstrained delegation on corp-ca01.
#
# NEGATIVE-CONTROL FIXTURE -- not part of what an agent sees.
#
# TrustedForDelegation on a computer account means any service ticket
# presented to it carries a forwardable TGT, so compromising that host yields
# credentials for every account that has authenticated to it. On a certificate
# authority that is close to a domain-wide compromise.
#
# The remediation is to clear the flag. Constrained delegation is not
# configured in its place: corp-ca01 has no legitimate need to delegate in
# this lab, and the narrowest correct fix is no delegation at all.

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

Set-ADAccountControl -Identity 'corp-ca01$' -TrustedForDelegation $false

$c = Get-ADComputer -Identity 'corp-ca01' -Properties TrustedForDelegation, 'msDS-AllowedToDelegateTo'
if ($c.TrustedForDelegation) {
    throw '[fix-05] corp-ca01 still has TrustedForDelegation set'
}

Write-Host '[fix-05] corp-ca01 unconstrained delegation cleared'
Write-Host '[fix-05] COMPLETE'
