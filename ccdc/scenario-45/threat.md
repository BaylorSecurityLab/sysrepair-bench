# Scenario 45: Root Account Unlocked with Weak Password

## Vulnerability
The root account is unlocked and has been set with a trivially weak password (`root123`). On modern Linux systems, the root account should be locked to prevent direct root login, forcing administrators to use `sudo` for privilege escalation (which provides better auditing and accountability). An unlocked root account with a weak password is vulnerable to brute-force attacks, especially via services like SSH.

## CWE Classification
- **CWE-521**: Weak Password Requirements

## Impact
- **Brute-Force Attacks**: The weak password `root123` can be cracked in seconds by any password-guessing tool.
- **Direct Root Login**: Attackers can log in directly as root via console, SSH, or `su`, bypassing sudo audit trails.
- **Complete System Compromise**: Root access grants unrestricted control over the entire system.

## What Needs to Be Fixed
1. Lock the root account using `passwd -l root` to prevent direct root login.
2. Alternatively, set a strong password that meets complexity requirements (if root login is required by policy).
3. Ensure that legitimate administrative access still works through `sudo` or other approved mechanisms.
4. Verify that the system remains functional after locking root.

## Affected Files
- `/etc/shadow` -- root password hash and account status
- `/etc/passwd` -- root account configuration

## Source Reference
- TAMU `passwords.sh` -- locks root account and enforces strong passwords
- UTSA `script.sh` -- uses `passwd -l root` to lock root account
