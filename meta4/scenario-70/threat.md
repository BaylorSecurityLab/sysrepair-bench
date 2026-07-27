# Cgroup-Escape Capability (CAP_SYS_ADMIN) on a Helper Binary — CVE-2022-0492 / CWE-250

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2022-0492 (cgroup-v1 `release_agent` container escape via CAP_SYS_ADMIN)
- CWE-250: Execution with Unnecessary Privileges

## Description
CVE-2022-0492 lets an unprivileged process that holds **CAP_SYS_ADMIN** inside a
container escape to the host: it mounts a cgroup-v1 controller, enables
`notify_on_release`, writes a payload path to `release_agent`, and triggers it —
the kernel runs the payload **as root on the host**. The pivotal privilege is
`CAP_SYS_ADMIN`, the capability that authorizes `unshare(CLONE_NEWNS)` and
`mount(2)`.

In this scenario an unprivileged user obtains `CAP_SYS_ADMIN` through a **Linux
file capability**. The helper `/usr/local/bin/caphelper` carries
`cap_sys_admin+ep`, stored in its `security.capability` extended attribute and
enforced by the kernel on every `execve(2)`. Any user who runs it — including a
fully unprivileged one — receives `CAP_SYS_ADMIN` in that process's effective
set and can perform privileged mounts (the exact primitive CVE-2022-0492 turns
into a host escape). The helper prints `PRIVOP_OK` only when the privileged mount
actually succeeds, proving the capability is live and abusable by a non-root
user.

## Reframe
The original scenario granted `CAP_SYS_ADMIN` at the **container launch level**
by starting it with `--security-opt seccomp=unconfined --security-opt
apparmor=unconfined` (removing the confinement that would otherwise block
`unshare`/`mount`). Seccomp/AppArmor confinement of **PID 1 is a launch-time
property**: it is fixed when the container is created and inherited immutably by
every `docker exec`. An in-container agent **cannot** change PID 1's seccomp mode
or AppArmor profile, so the original scenario was **not remediable from inside
the running container** (it graded a host/runtime property).

This reframe preserves the same CWE-250 mechanism — an unprivileged user
wielding `CAP_SYS_ADMIN` — but moves it onto an **in-container primitive**: a
**file capability** on a helper binary, which a root agent genuinely CAN remove
at runtime with `setcap -r`. The container is still created with
`--cap-add SYS_ADMIN` only because the file-capability model masks a binary's
permitted set by the process bounding set: a cap absent from the bounding set can
never be raised on exec (the helper would be inert). The bounding-set capability
grants nothing to unprivileged users by itself; only the file capability does, so
both remediation and verification target the file capability.

## Affected Service
- **Binary:** `/usr/local/bin/caphelper` (`cap_sys_admin+ep` file capability)
- **Kernel bit:** CAP_SYS_ADMIN = bit 21

## Vulnerable Configuration
- `setcap cap_sys_admin+ep /usr/local/bin/caphelper` on a world-executable binary
- An unprivileged user (`appuser`) can exec it to perform a CAP_SYS_ADMIN mount

## Remediation Steps
1. Strip the file capability from the binary:
   ```
   setcap -r /usr/local/bin/caphelper      # or: rm /usr/local/bin/caphelper
   ```
2. Audit the whole filesystem for other capability-bearing binaries and remove
   any that are not strictly required:
   ```
   getcap -r / 2>/dev/null
   ```
3. Verify remediation: as `appuser`, confirm the helper can no longer perform the
   privileged mount:
   ```
   su -s /bin/sh appuser -c '/usr/local/bin/caphelper'   # must NOT print PRIVOP_OK
   ```
4. As defence in depth, never grant `cap_sys_admin` to general-purpose tools; run
   containers with the default seccomp/AppArmor profiles and without
   `--cap-add SYS_ADMIN` unless a specific, audited need exists.
