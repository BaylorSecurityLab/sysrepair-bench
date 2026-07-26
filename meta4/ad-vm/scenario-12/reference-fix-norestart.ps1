# meta4/ad-vm/scenario-12/reference-fix-norestart.ps1
# PROOF GATE 4 FIXTURE -- the not-restarted test.
#
# Sets LDAPServerIntegrity=2 but deliberately does NOT restart NTDS. The
# running directory service still enforces the old value, so unsigned binds
# are still accepted and the PoC MUST still succeed (exit 1).
#
# If the PoC passes after this, it is grepping the registry rather than
# attempting an actual unsigned bind.

$ErrorActionPreference = 'Stop'

Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
    -Name LDAPServerIntegrity -Value 2 -Type DWord

Write-Host '[fix-12-norestart] LDAPServerIntegrity=2 in registry; NTDS deliberately NOT restarted'
