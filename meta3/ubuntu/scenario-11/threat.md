# docker Group Membership == Root (Privilege Escalation)

## Severity
**Critical** (CVSS 8.8)

## CVE / CWE
- CWE-269: Improper Privilege Management
- No individual CVE -- this is a well-documented design property of Docker
  (acknowledged by Docker Inc., referenced in Docker security documentation)

## Description
Any user who is a member of the `docker` group can trivially escalate to full
root on the host system. This is because:

1. The Docker daemon (`dockerd`) runs as root.
2. Members of the `docker` group can communicate with the daemon socket
   (`/var/run/docker.sock`) without `sudo`.
3. The daemon will honor requests to start containers with host filesystem
   mounts with no additional privilege checks.

An attacker with shell access to a user account in the `docker` group can
escape to root in a single command:

```bash
docker run -v /:/host -it --rm ubuntu:14.04 chroot /host /bin/bash
```

This mounts the host root filesystem at `/host` inside the container and
drops the attacker into a chroot with full root privileges over the host.

In the Metasploitable 3 design, the user `meta3admin` is placed in the
`docker` group, providing this escalation path to any attacker who gains
a shell as that user (e.g., via credential reuse from the payroll app).

## Affected Service
- **Surface:** Unix group membership
- **User:** meta3admin
- **Group:** docker
- **Socket:** /var/run/docker.sock (when daemon is running on host)

## Vulnerable Configuration
```
$ id meta3admin
uid=1001(meta3admin) gid=1001(meta3admin) groups=1001(meta3admin),999(docker)
```

## Remediation Steps
1. Remove `meta3admin` from the `docker` group:
   ```
   gpasswd -d meta3admin docker
   ```
2. Confirm the user still exists and can log in (do not delete the account):
   ```
   id meta3admin
   # must show uid, gid, groups= WITHOUT docker
   ```
3. If Docker access is required for operational reasons, use `sudo`-scoped
   access with explicit command allowlisting in `/etc/sudoers` rather than
   group membership.

## Build
```
docker build -f scenario-11/Dockerfile -t meta3u-s11 .
docker run -d --name meta3u-s11 meta3u-s11
docker exec meta3u-s11 /bin/bash /verify.sh
docker stop meta3u-s11 && docker rm meta3u-s11
```
