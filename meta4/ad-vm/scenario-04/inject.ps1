$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
Set-ADAccountControl -Identity dave -DoesNotRequirePreAuth $true
Set-ADAccountPassword -Identity dave -Reset -NewPassword (ConvertTo-SecureString 'Winter24' -AsPlainText -Force)
Write-Host "[inject-04] dave has DONT_REQ_PREAUTH + weak pwd (AS-REP roastable)"
