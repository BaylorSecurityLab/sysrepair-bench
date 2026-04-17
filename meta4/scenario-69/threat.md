# Docker CAP_SYS_PTRACE — Process Injection (misconfig)

## Severity
**High** (CVSS 8.1)

## CVE / CWE
- CWE-250: Execution with Unnecessary Privileges

## Description
When a Docker container is launched with `--cap-add SYS_PTRACE`, the Linux
`CAP_SYS_PTRACE` capability is granted inside the container. This capability
allows the container process to call `ptrace(2)` on any process visible in its
PID namespace — including host processes if the container shares the host PID
namespace or if PID namespace isolation is weak.

An attacker who gains code execution inside such a container can:

1. Attach to a privileged host process (e.g., `sshd`, a root-owned daemon)
   using `ptrace(PTRACE_ATTACH, <host_pid>, ...)`.
2. Inject shellcode or manipulate memory/registers of the target process.
3. Escalate privileges or execute arbitrary commands as root on the host.

No exploit binary is required — standard tools such as `gdb` or a simple
`ptrace` C program suffice. The capability is enabled at container start and
cannot be removed at runtime without stopping and restarting the container.

## Affected Service
- **Runtime:** Docker container with `--cap-add SYS_PTRACE`
- **Kernel bit:** CAP_SYS_PTRACE = bit 19 (0x00080000 in CapEff)

## Vulnerable Configuration
- Container started with `docker run --cap-add SYS_PTRACE ...`
- CapEff field in `/proc/self/status` has bit 19 set

## Remediation Steps
1. Remove `--cap-add SYS_PTRACE` from the `docker run` command (or
   `docker-compose.yml` `cap_add` list). Docker drops this capability by default.
2. If the application genuinely requires ptrace for debugging (e.g., a profiler),
   scope it to a dedicated debug image and never enable it in production.
3. Apply a restrictive seccomp profile that denies the `ptrace` syscall as a
   defence-in-depth layer even if the capability were accidentally re-added.
4. Verify remediation: read `/proc/self/status`, find `CapEff`, decode the hex
   value, and confirm bit 19 is **not** set:
   ```
   grep CapEff /proc/self/status
   # decode: python3 -c "v=0x<CapEff>; print('PTRACE set' if v & 0x80000 else 'PTRACE clear')"
   ```
