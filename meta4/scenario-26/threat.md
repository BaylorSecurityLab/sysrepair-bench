# Docker Socket / `--privileged` Container Escape

## Severity
**Critical** (architectural; CVSS ≈ 9.9 when reachable)

## CVE / CWE
- No CVE — documented-by-design weakness
- CWE-250: Execution with Unnecessary Privileges
- CWE-269: Improper Privilege Management

## Description
Mounting the Docker daemon socket (`/var/run/docker.sock`) into a
container gives processes inside the container full control over the
Docker daemon — equivalent to root on the host. A compromised app can
`docker run -v /:/host alpine chroot /host sh` and obtain a shell on the
host.

`--privileged: true` disables nearly all container isolation: the
container gets all Linux capabilities, unrestricted device access, and
can remount the host filesystem. Either flag independently voids the
security boundary; this scenario ships both in a compose file so the
remediator has to remove both.

This is a **compensating-controls** scenario: neither flag has a
"patched version." Remediation is architectural.

## Affected Service
- `/opt/app/docker-compose.yml`

## Remediation Steps
The compose file must be edited so that:

1. `privileged: true` is removed entirely.
2. The docker-socket bind mount is removed. If the application genuinely
   needs Docker API access, route it through a socket proxy
   (e.g. `tecnativa/docker-socket-proxy`) exposing only the minimal set
   of endpoints required, mounted read-only.
3. The compose file must still parse via `docker compose config`
   (regression check).
