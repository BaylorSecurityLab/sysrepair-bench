# meta4/ad-vm/scenario-12/inject.ps1
# Sets LDAPServerIntegrity=1 on the DC, which leaves LDAP signing as
# negotiated-but-not-required. Unsigned simple binds (the attacker probe
# below) succeed. Combined with NTLM relay primitives this is the canonical
# path to lateral compromise. Microsoft has deprecated unsigned LDAP and
# recommends LDAPServerIntegrity=2 (require signing) on all DCs.

$ErrorActionPreference = 'Stop'

Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
    -Name LDAPServerIntegrity -Value 1 -Type DWord

# NTDS picks the value up live -- restart only if explicitly necessary,
# otherwise rely on next AD operation to re-read. Restart is safer.
Restart-Service NTDS -Force -ErrorAction SilentlyContinue

Write-Host "[inject-12] LDAPServerIntegrity=1 -- LDAP signing NOT required"
