# meta4/ad-vm/scenario-03/inject.ps1
# Assigns an SPN to svc_sql, drops it back to RC4 encryption, and rotates
# its password to an 8-char dictionary value. Together this makes
# svc_sql Kerberoastable: any authenticated user can request a TGS for
# MSSQLSvc/..., the TGS is RC4-encrypted with svc_sql's NT hash as the key,
# and offline cracking finds the password in seconds.

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

Set-ADUser -Identity svc_sql -ServicePrincipalNames @{ Add = 'MSSQLSvc/corp-dc01.corp.local:1433' }
Set-ADAccountPassword -Identity svc_sql -Reset `
    -NewPassword (ConvertTo-SecureString 'Autumn24' -AsPlainText -Force)
Set-ADUser -Identity svc_sql -KerberosEncryptionType 'RC4'

Write-Host "[inject-03] svc_sql SPN=MSSQLSvc/... with RC4 + weak pwd (Kerberoastable)"
