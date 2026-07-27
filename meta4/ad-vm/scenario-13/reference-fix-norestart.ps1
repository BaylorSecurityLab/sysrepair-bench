# meta4/ad-vm/scenario-13/reference-fix-norestart.ps1
#
# GATE 4 DOES NOT APPLY TO THIS SCENARIO. This fixture exists only to record
# why, and deliberately makes no change.
#
# Gate 4 catches a remediation that is inert until a service reloads: write the
# correct configuration, skip the restart, and a check that merely READS
# configuration passes while the running service is still vulnerable.
#
# SMB signing has no such window. Set-SmbServerConfiguration
# -RequireSecuritySignature $true updates the running LanmanServer immediately;
# the negotiated security mode changes on the very next SMB2 session setup with
# no restart. The 2026-07-26 gate run measured exactly that -- gate 4 reported
# "not restarted" as False because the PoC correctly saw signing REQUIRED
# without any restart having happened.
#
# That is the check being right, not the check being config-only. And the PoC
# does not read configuration at all: nmap's smb2-security-mode negotiates a
# real SMB2 session and reports what the server advertised, so a stale-config
# gap could not fool it even if one existed.
#
# Same shape as scenario-12, where gate 4's premise was likewise false because
# LDAPServerIntegrity is consulted per connection. Keeping a fixture that
# asserts a false premise would manufacture a failure and invite someone to
# "fix" a check that is already correct.

$ErrorActionPreference = 'Stop'

Write-Host '[fix-13-norestart] GATE 4 NOT APPLICABLE to scenario-13.'
Write-Host '[fix-13-norestart] SMB signing takes effect on the next session setup,'
Write-Host '[fix-13-norestart] with no service restart. Making no change.'
