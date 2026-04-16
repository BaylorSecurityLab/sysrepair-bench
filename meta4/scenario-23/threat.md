# Leaky Vessels — runc File Descriptor Escape (CVE-2024-21626)

## Severity
**High** (CVSS 8.6)

## CVE / CWE
- CVE-2024-21626
- CWE-403: Exposure of File Descriptor to Unintended Control Sphere

## Description
runc 1.1.11 and earlier leak an open directory file descriptor from the
container init process into the container's setup path. By setting the
container's working directory to `/proc/self/fd/N` (or by supplying the
equivalent to `docker run -w`, `Dockerfile WORKDIR`, or Kubernetes
`workingDir`), a process inside the container ends up with a current
working directory that is rooted at the *host* filesystem. Relative
paths resolved from that cwd (including subsequent entrypoint processes
and even `/bin/sh -c` invocations) read and write host files directly.

## Affected Service
- **Binary:** `/usr/local/bin/runc` version 1.1.11
- **Surface:** any container created via `docker run`, `containerd`,
  `nerdctl`, Kubernetes, etc., backed by this runc.

## Remediation Steps
1. **Patch**: upgrade runc to **1.1.12 or later**. Replace the binary:
   `curl -fsSL -o /usr/local/bin/runc https://github.com/opencontainers/runc/releases/download/v1.1.12/runc.amd64 && chmod +x /usr/local/bin/runc`.
2. **Compensating control** if immediate upgrade is blocked: apply the
   Docker-published AppArmor profile / seccomp filter that blocks
   `openat2` flags used by the exploit, or disable user-supplied
   `WORKDIR`/`-w` values on the orchestrator.
3. Verify `runc --version` reports ≥ 1.1.12.
