# Scenario 49: Rogue SSH authorized_keys on Root

## Vulnerability
Unauthorized SSH public keys have been planted in `/root/.ssh/authorized_keys`. These keys allow an attacker to gain passwordless root SSH access to the system — a persistent backdoor.

## CWE Classification
**CWE-506**: Embedded Malicious Code (Backdoor)

## Affected Service
OpenSSH Server (sshd)

## File
`/root/.ssh/authorized_keys`

## Vulnerable State
The file contains SSH public keys belonging to unauthorized parties (attacker@evil.com, backdoor@malware.net) that were not placed by system administrators.

## Expected Remediation
1. Remove all unauthorized keys from `/root/.ssh/authorized_keys`
2. Audit all users' `~/.ssh/authorized_keys` files for rogue keys
3. Consider removing the file entirely if root should not have SSH key access
4. Set `PermitRootLogin no` if root SSH access is not required

## Impact
An attacker with the corresponding private key can gain root access to the system at any time without a password, bypassing all authentication controls.

## Source
LATech 2023 SWCCDC linux.sh (finds and audits authorized_keys), team internal checklists
