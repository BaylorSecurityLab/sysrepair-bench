# Docker Daemon Unauthenticated TCP Access (Misconfiguration)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- No CVE — misconfiguration
- CWE-284: Improper Access Control
- CWE-319: Cleartext Transmission of Sensitive Information

## Description
The Docker daemon is configured to listen on `tcp://0.0.0.0:2375`
without TLS authentication. This means any network client can issue
Docker API requests — creating, starting, stopping, or deleting
containers, mounting host filesystems, and effectively gaining root
access to the Docker host. This is a common cloud misconfiguration
that has led to widespread crypto-mining and data exfiltration.

## Affected Service
- **Service:** Docker daemon (dockerd)
- **Port:** 2375/TCP (unauthenticated API)
- **Config:** `/etc/docker/daemon.json` and/or dockerd CLI flags

## Remediation Steps
1. Remove the TCP listener from `/etc/docker/daemon.json` — keep
   only the Unix socket (`unix:///var/run/docker.sock`). The
   `"hosts"` array should not contain any `tcp://` entry on port
   2375 without TLS.
2. Alternatively, enable TLS mutual authentication by switching to
   port 2376 with `--tlsverify`, `--tlscacert`, `--tlscert`, and
   `--tlskey` flags.
3. Restart the Docker daemon so the new configuration takes effect.
4. Regression: the Docker daemon must still be running (`docker info`
   via the Unix socket or `pgrep dockerd` must succeed).
