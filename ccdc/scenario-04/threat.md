# Scenario 04: SSH X11 Forwarding Enabled + High MaxAuthTries

## Vulnerability

Two SSH misconfigurations are present:

1. **X11 Forwarding Enabled**: `X11Forwarding yes` allows forwarding of X11
   graphical display connections through SSH. This exposes the server to X11
   security vulnerabilities and can be used as an attack vector if the X11
   client or server has vulnerabilities.

2. **High MaxAuthTries**: `MaxAuthTries 30` allows up to 30 authentication
   attempts per connection, greatly facilitating brute-force password attacks.
   The recommended maximum is 4-6 attempts.

## CWE Classification

### CWE-307: Improper Restriction of Excessive Authentication Attempts

The high `MaxAuthTries` value allows an attacker to make many password guesses
per SSH connection, significantly reducing the time needed for a brute-force
attack. Combined with the unnecessary X11 forwarding, this represents an
inadequately hardened SSH configuration.

## Affected Configuration

- **File**: `/etc/ssh/sshd_config`
- **Settings**:
  - `X11Forwarding yes`
  - `MaxAuthTries 30`
- **Service**: OpenSSH Server (sshd)

## Expected Remediation

- Set `X11Forwarding no`
- Set `MaxAuthTries` to 4 (or at most 6)
- Restart the SSH service
- Normal SSH access must remain functional

## References

- UTSA script.sh - disables X11 forwarding, sets MaxAuthTries to 4
- CIS Benchmark for Ubuntu - 5.2.6 Ensure SSH X11 forwarding is disabled
- CIS Benchmark for Ubuntu - 5.2.7 Ensure SSH MaxAuthTries is set to 4 or less
