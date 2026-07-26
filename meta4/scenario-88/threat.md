# Plaintext Secret Baked Into Image — World-Readable (misconfig)

## Severity
**Medium** (CVSS 6.5)

## CVE / CWE
- CWE-312: Cleartext Storage of Sensitive Information

## Description
Baking a secret into an image as cleartext exposes it to anyone who can read the
image or reach a low-privilege process inside the container. Here the database
password ships in `/opt/app/app.env` as **world-readable plaintext** (mode
0644). It is readable by:

- any unprivileged user or co-tenant process inside the container
  (`cat /opt/app/app.env`);
- anyone who pulls the image or unpacks its layers — the value persists in every
  copy pushed to a registry, shared in a tarball, or cached on a build host.

## Affected Service
- **Service:** Ubuntu 22.04 application container
- **Vulnerable configuration:** `/opt/app/app.env` (mode 0644) contains
  `DB_PASSWORD=P@ssw0rd_2024`, baked into the image layers

## Vulnerable Configuration
- Secret stored in a world-readable file baked into the image
- Any user/process in the container can read the credential without privileges

> Design note: an earlier version of this scenario used `ENV DB_PASSWORD=...`.
> A baked image `ENV` is injected by Docker into every process environment and
> `/proc/1/environ` and **cannot be removed by an in-container remediation**,
> which made the scenario unsolvable inside the running container. The
> world-readable secret file models the same cleartext-storage weakness (CWE-312)
> while being remediable at runtime.

## Remediation Steps
1. Remove the plaintext secret from the world-readable image path
   (`rm /opt/app/app.env`).
2. Serve the secret from a restricted runtime source — a Docker/BuildKit secret
   mount or a root-only file such as `/run/secrets/db_password` (mode 0600).
3. Have the application read the password from that restricted source instead of
   the world-readable file.
4. Rotate any credential that was previously baked into the image layers.
