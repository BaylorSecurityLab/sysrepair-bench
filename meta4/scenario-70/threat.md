# Docker Cgroup Escape — CVE-2022-0492 (misconfig)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2022-0492
- CWE-862: Missing Authorization

## Description
CVE-2022-0492 is a Linux kernel vulnerability (fixed in 5.17-rc3) that allows
an unprivileged user inside a container to escape to the host via the cgroup
`notify_on_release` mechanism when:

1. The container has no seccomp filter (seccomp=unconfined), enabling the
   `unshare` syscall.
2. The container has no AppArmor profile (apparmor=unconfined), allowing
   arbitrary mounts.

An attacker creates a new user namespace with `unshare -UrmC`, mounts the
cgroup v1 filesystem, enables `notify_on_release` on a cgroup, writes a
payload path to `release_agent`, and then triggers the release by removing all
tasks from that cgroup. The kernel executes the release_agent **as root on the
host** with no containerization.

## Affected Service
- **Runtime:** Docker with seccomp=unconfined and apparmor=unconfined
- **Kernel:** Linux < 5.17-rc3 (patched), but misconfig is exploitable even on
  patched kernels without proper seccomp/AppArmor restrictions

## Vulnerable Configuration
- `docker run --security-opt seccomp=unconfined --security-opt apparmor=unconfined`
- `/proc/1/status` Seccomp field is `0` (disabled)
- `/proc/1/attr/current` is `unconfined`

## Remediation Steps
1. Apply Docker's default seccomp profile (do NOT pass `--security-opt seccomp=unconfined`).
   The default profile blocks `unshare` with `CLONE_NEWUSER`, preventing the
   user-namespace creation step of the exploit.
2. Apply the `docker-default` AppArmor profile (do NOT pass `--security-opt apparmor=unconfined`).
   This denies mount operations inside the container, breaking the cgroup mount step.
3. Verify seccomp is active: `/proc/1/status` Seccomp field must be `2` (FILTER mode).
4. Verify AppArmor is active: `/proc/1/attr/current` must NOT be `unconfined`.
5. As an additional layer, run as a non-root user inside the container (`--user`).
