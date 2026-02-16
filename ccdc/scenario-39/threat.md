# Scenario 39: /etc/shadow World-Readable

## Vulnerability
The `/etc/shadow` file has permissions `644` (world-readable), exposing password hashes to all users on the system. Any user can read the file and attempt offline password cracking.

## CWE Classification
**CWE-732**: Incorrect Permission Assignment for Critical Resource

## Affected Service
System authentication files

## File
`/etc/shadow`

## Vulnerable State
```
-rw-r--r-- root root /etc/shadow  (644 - world-readable)
```

## Expected Remediation
Set correct permissions:
```bash
chmod 640 /etc/shadow
chown root:shadow /etc/shadow
```
The file should only be readable by root and the shadow group.

## Impact
Any local user can read password hashes and perform offline brute-force cracking to obtain other users' passwords, including root.

## Source
LATech 2023 SWCCDC linux.sh (chown root:root, chmod), TAMU CCDC team checklists
