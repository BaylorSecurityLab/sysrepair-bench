# SUID-root Helper Binary — Non-root to Root Escalation (CWE-250)

## Severity
**High** (CVSS 8.2)

## CVE / CWE
- CWE-250: Execution with Unnecessary Privileges

## Description
A helper binary at `/usr/local/bin/suidhelper` is owned by root and carries the
**setuid bit** (`chmod 4755`). The Linux kernel sets the effective UID to the
file owner (root) on every `execve(2)` of a SUID binary, and the helper then
calls `setuid(0)`/`setgid(0)` to make its real, effective, and saved IDs all 0
before exec'ing `/bin/sh` with the caller's arguments. Consequently any
unprivileged user who runs it obtains a **root shell**:

```
su -s /bin/sh appuser -c '/usr/local/bin/suidhelper -c "cat /etc/shadow"'
```

reads `/etc/shadow` (mode 640, `root:shadow`) even though `appuser` has no rights
to it — a direct local privilege escalation. Shipping unnecessary,
privilege-bearing executables that any user can invoke is the classic CWE-250
weakness.

## Reframe
The original scenario disabled seccomp at the **container launch level** with
`--security-opt seccomp=unconfined`. The seccomp confinement of **PID 1 is a
launch-time property** — fixed when the container is created and inherited
immutably by every `docker exec`. An in-container agent **cannot** install a
seccomp filter on PID 1, so the original scenario graded a host/runtime property
that was **not remediable inside the running container**.

This reframe keeps the same CWE-250 mechanism — an unnecessary execution
privilege that lets a non-root user gain root — but expresses it as an
**in-container primitive** a root agent genuinely CAN fix: a **SUID-root helper
binary**. The remediation, `chmod u-s`, strips the setuid bit and removes the
escalation while leaving the binary in place.

## Affected Service
- **Binary:** `/usr/local/bin/suidhelper` (owned by root, mode `4755`)
- **Sensitive target reached:** `/etc/shadow` (and any root-only resource)

## Vulnerable Configuration
- `chmod 4755 /usr/local/bin/suidhelper` (setuid-root, world-executable)
- An unprivileged user (`appuser`) can exec it to run commands as root

## Remediation Steps
1. Strip the setuid bit from the helper (keep the file):
   ```
   chmod u-s /usr/local/bin/suidhelper
   ```
2. Audit the filesystem for other unexpected SUID-root binaries and remove the
   privilege from any that do not strictly require it:
   ```
   find / -xdev -type f -perm -4000 -user root 2>/dev/null
   ```
3. Verify remediation: as `appuser`, confirm the helper can no longer read a
   root-only file:
   ```
   su -s /bin/sh appuser -c '/usr/local/bin/suidhelper -c "cat /etc/shadow"'  # must be denied
   ```
4. As defence in depth, prefer capabilities scoped to a purpose-built binary over
   blanket SUID-root, and mount untrusted filesystems `nosuid`.
