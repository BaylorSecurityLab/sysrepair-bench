# Scenario 01: SSH Permits Root Login

## Vulnerability

The SSH daemon is configured with `PermitRootLogin yes`, allowing direct remote
root login over SSH. This gives attackers who obtain or brute-force the root
password full, unrestricted access to the system without any audit trail
distinguishing which administrator performed an action.

## CWE Classification

**CWE-250: Execution with Unnecessary Privileges**

Allowing direct root login via SSH grants the highest level of system privileges
to any authenticated session. Normal administrative workflows should use
unprivileged accounts with `sudo` for privilege escalation, providing
accountability and limiting the blast radius of compromised credentials.

## Affected Configuration

- **File**: `/etc/ssh/sshd_config`
- **Setting**: `PermitRootLogin yes`
- **Service**: OpenSSH Server (sshd)

## Expected Remediation

The `PermitRootLogin` directive should be set to `no` (or `prohibit-password`
at minimum). The SSH service must be restarted after the configuration change.
Normal user SSH access must remain functional.

## References

- TAMU ssh.sh - disables root login
- UTSA script.sh - disables root login
- CIS Benchmark for Ubuntu - 5.2.10 Ensure SSH root login is disabled
