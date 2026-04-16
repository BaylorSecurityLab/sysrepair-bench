# Dirty Pipe — Linux Pipe Splice Overwrite (CVE-2022-0847)

## Severity
**High** (CVSS 7.8)

## CVE / CWE
- CVE-2022-0847
- CWE-665: Improper Initialization (`PIPE_BUF_FLAG_CAN_MERGE`)

## Description
Linux kernel commit `f6dd975583bd` (v5.8) introduced a `struct pipe_buffer`
flag (`PIPE_BUF_FLAG_CAN_MERGE`) that was not zero-initialized when the
buffer came from `copy_page_to_iter_pipe` or `push_pipe`. An unprivileged
process can splice data from a read-only file into a pipe and then write
to the pipe, causing the kernel to overwrite the page cache of the
original file — bypassing file permissions (including read-only mounts,
SUID root binaries, and bind mounts).

This scenario is **kernel-level**: a container shares its host's kernel,
so this CVE is mitigated by patching the host kernel. The container
carries the userspace primitives (a SUID root marker file, PoC reference)
needed to train the remediation.

## Affected Service
- **Vulnerable kernels:** Linux 5.8 through 5.16.10 / 5.15.25 / 5.10.102
- **Host kernel is authoritative** (reported by `uname -r`)

## Remediation Steps
1. **Patch** (canonical fix): upgrade the host kernel to one of
   **5.16.11+, 5.15.26+, or 5.10.103+**.
2. **Compensating control** (if upgrade is blocked): set the immutable
   bit on security-sensitive SUID binaries —
   `chattr +i /opt/suid-marker` — which blocks the Dirty Pipe overwrite
   primitive at the filesystem layer.
3. Verify the marker binary still executes and returns `original`.
