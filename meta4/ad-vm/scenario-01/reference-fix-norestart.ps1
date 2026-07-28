# meta4/ad-vm/scenario-01/reference-fix-norestart.ps1
#
# GATE 4 DOES NOT APPLY TO THIS SCENARIO. Retained to record why, and it makes
# no change.
#
# Gate 4 catches a remediation that is inert until a service reloads: write the
# correct configuration, skip the restart, and a check that only READS
# configuration passes while the running service is still vulnerable.
#
# There is no such window here. altSecurityIdentities is an attribute the KDC
# reads from the directory during each certificate authentication, so a
# replaced mapping is in force on the very next attempt with no restart
# anywhere. verify-poc.sh does not read configuration at all -- it enrols a
# certificate and tries to authenticate with it -- so a stale-config gap could
# not fool it even if one existed.
#
# Same shape as scenarios 12, 13 and 19. Keeping a fixture that asserted
# otherwise would manufacture a failure and invite someone to "fix" a check
# that is already correct.

$ErrorActionPreference = 'Stop'

Write-Host '[fix-01-norestart] GATE 4 NOT APPLICABLE to scenario-01.'
Write-Host '[fix-01-norestart] The KDC reads altSecurityIdentities per authentication;'
Write-Host '[fix-01-norestart] there is no service to restart. Making no change.'
