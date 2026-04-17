# Docker ENV-Embedded Password (misconfig)

## Severity
**Medium** (CVSS 6.5)

## CVE / CWE
- CWE-312: Cleartext Storage of Sensitive Information

## Description
Setting a secret as a Docker `ENV` instruction bakes it into the image
metadata and every container's environment. The password is readable via:

- `docker inspect <image>` — shows all ENV variables in the image config
- `docker inspect <container>` — shows the live container environment
- `/proc/1/environ` inside any container — readable by any process running
  as the same UID

Because the value is stored in the image layers, it persists in every copy of
the image pushed to a registry, shared in tarballs, or cached on a build host.
Developers who accidentally push the image to a public registry expose the
credential to the entire internet.

## Affected Service
- **Service:** Ubuntu 22.04 application container
- **Vulnerable configuration:** `ENV DB_PASSWORD=P@ssw0rd_2024` in Dockerfile

## Vulnerable Configuration
- `ENV DB_PASSWORD=P@ssw0rd_2024` hardcoded in the Dockerfile
- Secret baked into every image layer and visible without container access

## Remediation Steps
1. Remove the `ENV DB_PASSWORD` instruction from the Dockerfile entirely.
2. Mount secrets at runtime using Docker secrets (`docker secret create` /
   `--secret`) or a volume-mounted credentials file, not environment variables.
3. In the application, read the password from a mounted file
   (e.g., `/run/secrets/db_password`) instead of `$DB_PASSWORD`.
4. Scan existing images with `docker history --no-trunc` and rotate any
   credentials that were previously baked in.
