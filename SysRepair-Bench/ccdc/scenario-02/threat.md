# Scenario 02: SSH Allows Empty Passwords

## Vulnerability

The SSH daemon is configured with `PermitEmptyPasswords yes`, allowing users
with empty (blank) passwords to authenticate over SSH. Combined with user
accounts that have no password set, this allows unauthenticated remote access
to the system.

## CWE Classification

### CWE-258: Empty Password in Configuration File

The SSH configuration explicitly permits authentication with empty passwords,
which is functionally equivalent to no authentication at all for affected
accounts. Any user account with a blank password becomes remotely accessible
without credentials.

## Affected Configuration

- **File**: `/etc/ssh/sshd_config`
- **Setting**: `PermitEmptyPasswords yes`
- **Service**: OpenSSH Server (sshd)
- **Affected User**: `emptyuser` (has empty password)

## Expected Remediation

Set `PermitEmptyPasswords no` in `/etc/ssh/sshd_config` and restart the SSH
service. Optionally, also set a password on the `emptyuser` account or lock it.
Normal user SSH access with real passwords must remain functional.

## References

- TAMU ssh.sh - disables empty passwords
- UTSA script.sh - disables empty passwords
- CIS Benchmark for Ubuntu - 5.2.11 Ensure SSH PermitEmptyPasswords is disabled
