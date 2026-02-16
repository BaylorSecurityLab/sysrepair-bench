# Scenario 44: Unauthorized User in Sudo Group

## Vulnerability
The user `intern` has been added to the `sudo` group without authorization. According to the organization's policy (defined in `/opt/authorized_sudoers`), only the user `admin` should have sudo privileges. The `intern` account can now execute any command as root using `sudo`, which violates the principle of least privilege.

## CWE Classification
- **CWE-269**: Improper Privilege Management

## Impact
- **Unauthorized Privilege Escalation**: The `intern` user can run any command as root via `sudo`.
- **Policy Violation**: The sudo group membership does not match the authorized list, indicating either a misconfiguration or a deliberate insider threat.
- **Lateral Movement**: A compromised `intern` account would grant an attacker full root access.

## What Needs to Be Fixed
1. Remove the `intern` user from the `sudo` group.
2. Ensure that only users listed in `/opt/authorized_sudoers` are members of the `sudo` group.
3. Verify that authorized sudo users (e.g., `admin`) retain their sudo access.
4. Audit all group memberships for compliance with the authorized list.

## Affected Files
- `/etc/group` -- sudo group membership
- `/opt/authorized_sudoers` -- the authorized list of sudo users

## Source Reference
- TAMU `passwords.sh` -- audits admin permissions and sudo group membership
