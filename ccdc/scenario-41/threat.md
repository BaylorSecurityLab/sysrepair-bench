# Scenario 41: SUID Bit on Python3/Perl Interpreters

## Vulnerability
The SUID (Set User ID) bit has been set on the `python3` and `perl` interpreter binaries. When the SUID bit is set on an interpreter, any user on the system can execute scripts that run with root privileges. This is a well-known privilege escalation vector: an unprivileged user can simply run `python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'` to obtain a root shell.

## CWE Classification
- **CWE-269**: Improper Privilege Management

## Impact
- **Privilege Escalation**: Any local user can gain full root access to the system.
- **Complete System Compromise**: Attackers with any level of shell access can escalate to root, read/modify any file, install backdoors, or pivot to other systems.

## What Needs to Be Fixed
1. Remove the SUID bit from all python3 and perl interpreter binaries (`chmod u-s`).
2. Ensure the interpreters still function correctly for normal (non-privileged) use.
3. Audit the system for any other interpreters or binaries with unnecessary SUID bits.

## Affected Files
- `/usr/bin/python3*`
- `/usr/bin/perl`

## Source Reference
- TAMU `check_suid.sh` -- audits binaries with SUID bits set
