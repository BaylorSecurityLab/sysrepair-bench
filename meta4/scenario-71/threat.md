# Docker seccomp=unconfined — All Syscalls Allowed (misconfig)

## Severity
**High** (CVSS 8.2)

## CVE / CWE
- CWE-250: Execution with Unnecessary Privileges

## Description
Docker's default seccomp profile blocks ~44 syscalls that are dangerous in a
container context (e.g., `unshare`, `keyctl`, `perf_event_open`,
`ptrace` with CLONE_NEWUSER, `kexec_load`). When a container is launched with
`--security-opt seccomp=unconfined`, this filter is disabled and every syscall
supported by the host kernel is accessible from inside the container.

This dramatically widens the container's attack surface:

- **Namespace escapes:** `unshare(CLONE_NEWUSER)` can be used as a building
  block for privilege escalation attacks (e.g., CVE-2022-0492).
- **Kernel exploit surface:** Dangerous syscalls like `perf_event_open` and
  `ptrace` are available, enabling exploitation of kernel vulnerabilities that
  the default profile would block.
- **Key material theft:** `keyctl` is unrestricted, allowing reading kernel
  keyrings that may hold host credentials.

The `/proc/1/status` `Seccomp` field reports `0` when disabled and `2` when
Docker's default FILTER profile is active.

## Affected Service
- **Runtime:** Docker container with `--security-opt seccomp=unconfined`
- **Status indicator:** `/proc/1/status` Seccomp = 0

## Vulnerable Configuration
- `docker run --security-opt seccomp=unconfined ...`
- Seccomp field in `/proc/1/status` is `0` (SECCOMP_MODE_DISABLED)

## Remediation Steps
1. Remove `--security-opt seccomp=unconfined` from the `docker run` command or
   compose file. Docker applies the default seccomp profile automatically.
2. If a specific syscall is needed that the default profile blocks, create a
   custom profile that allows only that syscall rather than disabling seccomp
   entirely.
3. Verify remediation: `grep '^Seccomp:' /proc/1/status` must return `2`.
4. Test that the application still functions correctly after re-enabling seccomp.
