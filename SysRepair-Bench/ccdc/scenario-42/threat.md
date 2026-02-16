# Scenario 42: World-Writable /tmp Without Sticky Bit

## Vulnerability
The `/tmp` directory has been set to mode `0777` (world-writable) without the sticky bit. The correct permissions for `/tmp` should be `1777`, where the leading `1` represents the sticky bit. Without the sticky bit, any user can delete, rename, or overwrite files created by other users in `/tmp`, enabling symlink attacks, race conditions, and denial-of-service scenarios.

## CWE Classification
- **CWE-732**: Incorrect Permission Assignment for Critical Resource

## Impact
- **Data Integrity**: Any user can delete or modify temporary files belonging to other users or system services.
- **Symlink Attacks**: Attackers can replace legitimate temp files with symlinks to sensitive files, leading to privilege escalation.
- **Denial of Service**: Critical temporary files used by services can be deleted, causing service failures.

## What Needs to Be Fixed
1. Set the sticky bit on `/tmp` by changing permissions to `1777` (`chmod 1777 /tmp` or `chmod +t /tmp`).
2. Verify that `/tmp` remains writable by all users (the world-writable bits must stay).
3. Audit other shared directories (e.g., `/var/tmp`) for the same issue.

## Affected Files
- `/tmp` directory permissions

## Source Reference
- TAMU `set_sticky_bit.sh` -- sets sticky bit on world-writable directories
