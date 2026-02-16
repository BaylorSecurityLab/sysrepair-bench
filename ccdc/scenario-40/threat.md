# Scenario 40: /etc/passwd Writable by Others

## Vulnerability
The `/etc/passwd` file has permissions `666` (world-writable), allowing any user to modify it. An attacker can add new users, change UIDs to 0 (root), or modify shell assignments to gain unauthorized access.

## CWE Classification
**CWE-732**: Incorrect Permission Assignment for Critical Resource

## Affected Service
System authentication files

## File
`/etc/passwd`

## Vulnerable State
```
-rw-rw-rw- root root /etc/passwd  (666 - world-writable)
```

## Expected Remediation
Set correct permissions:
```bash
chmod 644 /etc/passwd
chown root:root /etc/passwd
```

## Impact
Any local user can add a UID 0 account, change their shell, or modify other users' entries. This is a trivial privilege escalation path.

## Source
LATech 2023 SWCCDC linux.sh (chown root:root /etc/passwd)
