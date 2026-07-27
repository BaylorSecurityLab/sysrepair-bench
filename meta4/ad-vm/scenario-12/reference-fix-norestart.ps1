# meta4/ad-vm/scenario-12/reference-fix-norestart.ps1
#
# GATE 4 DOES NOT APPLY TO THIS SCENARIO. This fixture is retained only to
# document why, and it deliberately does NOT assert the gate-4 expectation.
#
# Gate 4 (the not-restarted test) assumes a remediation that is inert until the
# service reloads: write the correct configuration, skip the restart, and a
# check that merely reads configuration will wrongly pass while the running
# service is still vulnerable.
#
# That assumption is FALSE for LDAP signing. Measured against the live lab:
# setting LDAPServerIntegrity=2 WITHOUT restarting NTDS caused the DC to reject
# an unsigned simple bind on the very next connection. The value is consulted
# per connection, not cached at service start.
#
# So gate 4 reported "config-only check" for scenario-12 when the check is
# behavioural and correct -- the FIXTURE encoded a false premise, not the
# scenario. Microsoft's guidance to restart after changing the policy is about
# making the change durable and consistent, not about when it starts being
# enforced.
#
# Keeping a fixture that scores a correct check as defective would be worse
# than having none: it manufactures a failure and invites someone to "fix" a
# check that is already right.
#
# If this scenario ever grows a remediation that IS restart-dependent, this
# file should be rewritten to exercise that instead.

$ErrorActionPreference = 'Stop'

Write-Host '[fix-12-norestart] GATE 4 NOT APPLICABLE to scenario-12.'
Write-Host '[fix-12-norestart] LDAPServerIntegrity is read per connection, so it takes'
Write-Host '[fix-12-norestart] effect without an NTDS restart. There is no config-only'
Write-Host '[fix-12-norestart] state for this remediation to be caught in.'
Write-Host '[fix-12-norestart] Making no change; see the comments in this file.'
