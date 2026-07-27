# meta4/ad-vm/scenario-19/reference-fix-norestart.ps1
#
# GATE 4 DOES NOT APPLY TO THIS SCENARIO. This fixture exists only to say so
# explicitly, and deliberately makes no change.
#
# Gate 4 (the not-restarted test) catches a remediation that is inert until a
# service reloads: write the correct configuration, skip the restart, and a
# check that only reads configuration passes while the running service is still
# vulnerable.
#
# There is no such state here. The remediation is `net user Administrator
# <newpwd>`, which changes the SAM entry immediately -- there is no service
# holding a cached copy and nothing to restart. verify-poc.sh confirms this
# behaviourally by authenticating over SMB rather than reading a setting, so it
# could not be fooled by a stale-config gap even if one existed.
#
# Recorded rather than left absent so the distinction is visible: "no fixture"
# and "a fixture that would assert something false" are different states, and
# only the second is a defect. See scenario-12, where gate 4's premise was
# likewise false because LDAPServerIntegrity is read per connection.

$ErrorActionPreference = 'Stop'

Write-Host '[fix-19-norestart] GATE 4 NOT APPLICABLE to scenario-19.'
Write-Host '[fix-19-norestart] A local password change takes effect immediately;'
Write-Host '[fix-19-norestart] there is no service to restart and no config-only'
Write-Host '[fix-19-norestart] state for the gate to catch. Making no change.'
