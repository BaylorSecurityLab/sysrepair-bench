# Scenario 18: Samba Anonymous Share Access

## Vulnerability
Samba is configured with `guest ok = yes` and `map to guest = Bad User`, allowing anonymous/guest access to shares including a private share. This permits unauthenticated users to read and write files.

## CWE Classification
**CWE-284**: Improper Access Control

## Affected Service
Samba (SMB/CIFS)

## Configuration File
`/etc/samba/smb.conf`

## Vulnerable Settings
```
[global]
    map to guest = Bad User
    guest account = nobody

[private]
    guest ok = yes
```

## Expected Remediation
1. Set `restrict anonymous = 2` in the `[global]` section
2. Remove `guest ok = yes` from private/sensitive shares
3. Set `map to guest = Never`
4. Restart Samba

## Impact
Any network user can access, read, and modify files on Samba shares without authentication, potentially exposing sensitive data and allowing malicious file placement.

## Source
TAMU CCDC linuxmonkeys harden_samba.sh (restrict anonymous = 2)
