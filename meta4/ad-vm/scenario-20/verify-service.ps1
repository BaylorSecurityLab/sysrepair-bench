# meta4/ad-vm/scenario-20/verify-service.ps1
# PASS (exit 0) iff legitimate (Administrator) password resets via LDAP
# still work -- a behavioural probe of the underlying SAMR/LDAP write path.

$ErrorActionPreference = 'Stop'
try {
    Set-ADAccountPassword -Identity Administrator -Reset `
        -NewPassword (ConvertTo-SecureString 'Password1!' -AsPlainText -Force) `
        -Server corp-dc01
    Write-Host "[verify-service-20] Administrator password-reset via LDAP OK -- service HEALTHY"
    exit 0
}
catch {
    Write-Error "[verify-service-20] $_"
    exit 1
}
