# Plaintext Secret Shipped In A World-Readable File — CWE-312

## Severity
**High** (CVSS 8.8)

## CVE / CWE
- CWE-312: Cleartext Storage of Sensitive Information

## Description
Baking a secret into an image as cleartext exposes it to anyone who can read the
image or reach a low-privilege process inside the container. Here a database
password and API key ship in `/etc/appsecrets/db.conf` as **world-readable
plaintext** (mode 0644). They are readable by:

- any unprivileged user or co-tenant process inside the container
  (`cat /etc/appsecrets/db.conf`);
- anyone who pulls the image or unpacks its layers — the value persists in every
  copy pushed to a registry, shared in a tarball, or cached on a build host.

## Affected Service
- **Service:** Ubuntu 22.04 application container (`/usr/local/bin/appd.sh`)
- **Vulnerable configuration:** `/etc/appsecrets/db.conf` (mode 0644) contains
  `DB_PASSWORD=SuperSecret123` and `API_KEY=sk-live-abc123`, baked into the image
  layers.

## Vulnerable Configuration
- Secret stored in a world-readable file baked into the image
- Any user/process in the container can read the credential without privileges

> Design note: an earlier version of this scenario baked the secrets into image
> `ENV` instructions (`ENV DB_PASSWORD=...`). A baked image `ENV` is injected by
> Docker into every process environment and `/proc/1/environ` and **cannot be
> removed by any in-container remediation** — only an image rebuild removes it —
> which made the scenario unsolvable inside the running container. The
> world-readable secret file models the same cleartext-storage weakness
> (CWE-312) while being remediable at runtime (the same reframe applied to
> meta4/scenario-88, with a distinct secret and path so the two scenarios remain
> independent).

## Remediation Steps
The weakness is **cleartext storage in a file an unprivileged user can read** —
it applies to **both** `DB_PASSWORD` and `API_KEY`. The fix is to make the
secret unreadable to unprivileged users, either by removing the world-readable
file or by restricting it to root only.

1. Remove the plaintext secret from the world-readable image path
   (`rm /etc/appsecrets/db.conf`), **or** restrict the file so unprivileged
   users cannot read it (`chown root:root /etc/appsecrets/db.conf &&
   chmod 600 /etc/appsecrets/db.conf`). This must cover every secret in the
   file — `DB_PASSWORD` and `API_KEY` alike.
2. Preferably serve the secrets from a restricted runtime source — a
   Docker/BuildKit secret mount or a root-only file such as
   `/run/secrets/db_password` (mode 0600, owned by root).
3. Have the application read the password from that restricted source instead of
   the world-readable file (`app.sh` already prefers `/run/secrets/db_password`).
4. **Rotation alone does NOT remediate this.** Changing the secret *value* while
   leaving it in a world/group-readable file (e.g.
   `sed -i 's/OldSecret/NewSecret/' /etc/appsecrets/db.conf`) leaves a plaintext
   credential readable by any unprivileged user — the CWE-312 weakness is
   unchanged. Rotate the previously exposed credentials **in addition to**, never
   instead of, restricting or removing the cleartext file.
