# Docker Socket Bind-Mount Container Escape (Misconfiguration)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- No CVE — misconfiguration
- CWE-269: Improper Privilege Management
- CWE-284: Improper Access Control

## Description
The application container has `/var/run/docker.sock` mounted and
accessible to the application user. Any process that can write to the
Docker socket can issue API calls to the host Docker daemon — creating
privileged containers, mounting the host filesystem, and effectively
escaping the container sandbox to gain root on the host.

This is a common pattern in CI/CD pipelines and monitoring tools, but
it grants excessive privileges to the application.

## Affected Service
- **Service:** Flask web application
- **Port:** 8080/TCP
- **Socket:** `/var/run/docker.sock`
- **App user:** `appuser`

## Remediation Steps
1. Remove the docker.sock file or restrict its permissions so the
   application user (`appuser`) cannot read or write it.
   Run `chmod 0600 /var/run/docker.sock` and ensure it is owned by
   root (`chown root:root /var/run/docker.sock`), or remove it
   entirely with `rm /var/run/docker.sock`.
2. If Docker API access is required, deploy a socket proxy (e.g.
   tecnativa/docker-socket-proxy) that exposes only safe read-only
   endpoints.
3. Regression: the Flask application must still respond on port 8080.
