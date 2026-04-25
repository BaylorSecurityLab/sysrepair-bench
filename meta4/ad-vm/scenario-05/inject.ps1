# meta4/ad-vm/scenario-05/inject.ps1
# Flags corp-ca01's computer account as TrustedForDelegation (unconstrained).
# Once set, any service ticket the DC issues to corp-ca01 is forwardable,
# and any principal that authenticates to corp-ca01 hands over their TGT
# via S4U2self. An attacker with code exec on corp-ca01 can then replay
# Administrator's TGT to DCSync corp-dc01.

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
Set-ADAccountControl -Identity 'corp-ca01$' -TrustedForDelegation $true
Write-Host "[inject-05] corp-ca01 TrustedForDelegation=True -- unconstrained delegation set"
