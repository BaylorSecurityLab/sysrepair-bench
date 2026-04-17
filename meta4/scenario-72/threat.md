# Docker AppArmor=unconfined — No MAC Enforcement (misconfig)

## Severity
**High** (CVSS 8.1)

## CVE / CWE
- CWE-250: Execution with Unnecessary Privileges

## Description
Docker's `docker-default` AppArmor profile restricts what a container process
can do at the kernel MAC (Mandatory Access Control) level — denying dangerous
mount operations, writes to sensitive `/proc` and `/sys` paths, and raw socket
creation. When a container is started with `--security-opt apparmor=unconfined`,
AppArmor enforcement is completely disabled.

Without MAC enforcement an attacker with code execution inside the container can:

- Mount filesystems (including cgroup and proc pseudo-filesystems) that are
  blocked by the default profile, enabling CVE-2022-0492-style escapes.
- Write to `/proc/sysrq-trigger` and other sensitive kernel interfaces.
- Use raw sockets for network sniffing and spoofing.
- Perform operations that could interact with the host kernel in ways blocked
  by MAC policy.

AppArmor provides a crucial defence-in-depth layer that complements seccomp.
Disabling it removes an entire enforcement layer from the security model.

## Affected Service
- **Runtime:** Docker container with `--security-opt apparmor=unconfined`
- **Status indicator:** `/proc/1/attr/current` = `unconfined`

## Vulnerable Configuration
- `docker run --security-opt apparmor=unconfined ...`
- `/proc/1/attr/current` contains `unconfined`

## Remediation Steps
1. Remove `--security-opt apparmor=unconfined` from the `docker run` command or
   compose file. Docker loads the `docker-default` AppArmor profile automatically
   on hosts where AppArmor is enabled.
2. If a custom profile is required, create one with `aa-genprof` and load it
   via `--security-opt apparmor=<profile-name>` rather than disabling AppArmor.
3. Verify remediation: `cat /proc/1/attr/current` must NOT contain `unconfined`.
   It should contain a string like `docker-default (enforce)`.
4. On hosts where AppArmor is not available, use seccomp as the primary MAC
   layer and document the absence of AppArmor as an accepted risk.
