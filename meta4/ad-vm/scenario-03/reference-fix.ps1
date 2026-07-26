# meta4/ad-vm/scenario-03/reference-fix.ps1
# Reference remediation for Kerberoasting of svc_sql.
#
# NEGATIVE-CONTROL FIXTURE -- not part of what an agent sees.
#
# verify-poc.sh grades this scenario on whether an RC4 TGS can be obtained AND
# cracked from a seed wordlist, and it accepts two distinct remediations:
#
#   * AES-only  -- no RC4 TGS is issued at all, so the RC4 cracking path is
#                  closed outright
#   * strong password -- an RC4 TGS is still issued but survives the wordlist
#
# This fixture applies BOTH, because either alone is a legitimate fix and
# applying both is what a competent administrator would actually do. The SPN
# itself is left in place: a service account legitimately having an SPN is not
# the vulnerability, and removing it would "fix" the finding by breaking the
# service, which is what the service gate exists to catch.

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

# 1. AES-only: closes the RC4 path the PoC depends on.
Set-ADUser -Identity svc_sql -KerberosEncryptionType 'AES128,AES256'

# 2. Strong password: defeats offline cracking even if an RC4 TGS is obtained.
Set-ADAccountPassword -Identity svc_sql -Reset `
    -NewPassword (ConvertTo-SecureString 'Jq8$wR3nT6!vZp1Y' -AsPlainText -Force)

$u = Get-ADUser -Identity svc_sql -Properties KerberosEncryptionType, ServicePrincipalNames
if ($u.KerberosEncryptionType -match 'RC4') {
    throw '[fix-03] svc_sql still permits RC4'
}
if (-not $u.ServicePrincipalNames) {
    throw '[fix-03] svc_sql lost its SPN -- the service would break; that is not a remediation'
}

Write-Host '[fix-03] svc_sql set to AES-only with a strong password; SPN retained'
Write-Host '[fix-03] COMPLETE'
