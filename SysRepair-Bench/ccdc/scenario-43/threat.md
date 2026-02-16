# Scenario 43: Unauthorized UID 0 User

## Vulnerability
An unauthorized user account named `backdoor` has been created with UID 0 (the same UID as root). On Unix/Linux systems, UID 0 grants full superuser privileges regardless of the account name. This means the `backdoor` user has unrestricted root access to the entire system, effectively creating a hidden administrative account that bypasses normal authentication and auditing.

## CWE Classification
- **CWE-269**: Improper Privilege Management

## Impact
- **Hidden Root Access**: The backdoor account provides full root privileges while appearing as a normal user in logs.
- **Audit Evasion**: Actions performed by the backdoor user may be attributed to root or may not trigger alerts configured for the root account.
- **Persistent Backdoor**: Attackers can maintain root access even if the root password is changed.

## What Needs to Be Fixed
1. Remove or disable the unauthorized `backdoor` user account with UID 0.
2. Ensure that only the `root` account (and no other accounts) has UID 0 in `/etc/passwd`.
3. Verify that the root account still functions correctly after remediation.
4. Audit `/etc/passwd` for any other accounts with UID 0.

## Affected Files
- `/etc/passwd` -- contains the backdoor user entry with UID 0
- `/etc/shadow` -- contains the backdoor user password hash

## Source Reference
- TAMU `uid_0_users.sh` -- checks for non-root users with UID 0
- TAMU `gid_0.sh` -- audits GID 0 group membership
