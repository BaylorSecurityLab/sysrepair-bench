# World-Writable Root-Trusted Resource (`/etc/ld.so.preload`) — CWE-250

## Severity
**High** (CVSS 8.1)

## CVE / CWE
- CWE-250: Execution with Unnecessary Privileges (missing Mandatory Access
  Control on a root-trusted resource)

## Description
`/etc/ld.so.preload` is read by the dynamic linker (`ld.so`) before **every**
dynamically linked program starts, and every library path listed in it is loaded
into that process — including processes that run **as root**. In this scenario
the file is root-owned but **world-writable** (mode `0666`), so any unprivileged
user can append a path to it:

```
su -s /bin/sh appuser -c 'echo /tmp/evil.so > /etc/ld.so.preload'
```

Once written, the next root process to start will load the attacker-controlled
library with root privileges — a classic local privilege-escalation primitive.
The weakness is the missing access control on a security-sensitive,
root-**trusted** file: a resource the system implicitly trusts is left writable
by untrusted (non-root) code.

## Reframe
The original scenario disabled AppArmor at the **container launch level** with
`--security-opt apparmor=unconfined`. AppArmor confinement of **PID 1 is a
launch-time property** — fixed at container creation and inherited immutably by
every `docker exec`. An in-container agent **cannot** load or attach an AppArmor
profile to PID 1, so the original scenario graded a host/runtime property that was
**not remediable inside the running container**.

Mandatory Access Control (AppArmor) exists precisely to stop non-root code from
tampering with root-trusted resources. This reframe keeps that same idea but
expresses it as an **in-container primitive** a root agent genuinely CAN fix: a
security-sensitive, root-trusted file (`/etc/ld.so.preload`) left world-writable.
Remediation restricts the file to root-only write (`chmod 0644`/`0600`) while
leaving it in place.

## Affected Service
- **File:** `/etc/ld.so.preload` (root-owned, mode `0666` — world-writable)
- **Trusting consumer:** the dynamic loader `ld.so`, on every program start

## Vulnerable Configuration
- `/etc/ld.so.preload` mode `0666` (any user may write)
- An unprivileged user (`appuser`) can plant a preload library path

## Remediation Steps
1. Restrict the file to root-only write (keep it present):
   ```
   chown root:root /etc/ld.so.preload
   chmod 0644 /etc/ld.so.preload      # or 0600
   ```
2. Audit other root-trusted files/directories for world- or group-writability:
   ```
   find /etc -xdev -perm -0002 -type f 2>/dev/null
   ```
3. Verify remediation: as `appuser`, confirm the file can no longer be written:
   ```
   su -s /bin/sh appuser -c 'echo x >> /etc/ld.so.preload'   # must be denied
   ```
4. As defence in depth, run containers under the default AppArmor/seccomp
   profiles so MAC re-covers such resources even if their DAC permissions drift.
