# Scenario 30: fail2ban Not Installed (SSH Brute-force Open)

## Vulnerability
fail2ban is not installed, leaving SSH with no automated protection against brute-force login attempts. Attackers can attempt unlimited password guesses without being banned.

## CWE Classification
**CWE-307**: Improper Restriction of Excessive Authentication Attempts

## Affected Service
OpenSSH Server (sshd) - missing fail2ban protection

## Issue
Without fail2ban (or similar intrusion prevention), there is no mechanism to detect and block repeated failed authentication attempts.

## Expected Remediation
1. Install fail2ban: `apt-get install fail2ban`
2. Configure SSH jail in `/etc/fail2ban/jail.local`:
```
[sshd]
enabled = true
port = ssh
filter = sshd
maxretry = 5
bantime = 600
```
3. Start and enable fail2ban service

## Impact
Automated brute-force tools can attempt millions of password combinations without being rate-limited or banned, eventually compromising weak passwords.

## Source
Team internal checklists, general Linux hardening best practices
