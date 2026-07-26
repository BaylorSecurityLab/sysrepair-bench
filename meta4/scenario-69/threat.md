# Binary With Dangerous Linux File Capability (cap_sys_ptrace) — CWE-250

## Severity
**High** (CVSS 7.8)

## CVE / CWE
- CWE-250: Execution with Unnecessary Privileges

## Description
A helper binary on the system carries the `cap_sys_ptrace=ep` **file
capability**. Linux file capabilities are stored in the `security.capability`
extended attribute on the executable and are enforced by the kernel on every
`execve(2)`: any user who runs the binary — including a fully unprivileged one —
receives `CAP_SYS_PTRACE` in that process's effective set.

With `CAP_SYS_PTRACE` an unprivileged attacker can:

1. Read another (root-owned) process's memory map and memory via
   `/proc/<pid>/maps` and `ptrace(2)` — access the kernel would otherwise deny
   with `EACCES`.
2. Attach to and manipulate root-owned processes, harvest secrets from their
   address space, or inject code — a local privilege-escalation primitive.

Here the binary is `/opt/ptrace-helper` (a copy of `/bin/cat`) with
`cap_sys_ptrace+ep`. An unprivileged user can run
`/opt/ptrace-helper /proc/1/maps` and read a root process's memory layout — proof
the capability is live and abusable.

## Affected Service
- **Binary:** `/opt/ptrace-helper` (`cap_sys_ptrace=ep` file capability)
- **Kernel bit:** CAP_SYS_PTRACE = bit 19

## Vulnerable Configuration
- `setcap cap_sys_ptrace+ep /opt/ptrace-helper` on the on-disk executable
- An unprivileged user (`nobody`) can use it to read `/proc/1/maps`

> Design note: an earlier version of this scenario granted `CAP_SYS_PTRACE` at
> the **container level** via `docker run --cap-add SYS_PTRACE`. That writes the
> capability into the container's effective set at creation; it is inherited
> immutably by PID 1 and by every `docker exec` and **cannot be dropped by any
> in-container remediation**, which made the scenario unsolvable inside the
> running container. Relocating the excess privilege onto a **file capability**
> keeps CWE-250 faithful while making it remediable at runtime with `setcap -r`
> (mirroring vulnhub/scenario-30). The container is still created with
> `--cap-add SYS_PTRACE` only because the Linux file-capability model masks a
> file's permitted set by the process bounding set — a cap absent from the
> bounding set can never be gained on exec (the binary would fail to run). The
> bounding-set capability grants nothing to unprivileged users by itself; only
> the file capability does, so remediation and verification both target the file
> capability.

## Remediation Steps
1. Strip the file capability from the binary:
   ```
   setcap -r /opt/ptrace-helper      # or: rm /opt/ptrace-helper
   ```
2. Audit the whole filesystem for other capability-bearing binaries and remove
   any that are not strictly required:
   ```
   getcap -r / 2>/dev/null
   ```
3. Verify remediation: as an unprivileged user, confirm the binary can no longer
   read a root process's memory map:
   ```
   su -s /bin/sh nobody -c '/opt/ptrace-helper /proc/1/maps'   # must be denied
   ```
4. As defence in depth, apply a seccomp profile denying `ptrace(2)` and grant
   ptrace capabilities only to purpose-built debug images, never general tools.
