# Rsync Daemon — No Authentication / No ACL (misconfig)

## Severity
**Critical** (CVSS 9.1)

## CVE / CWE
- CWE-284: Improper Access Control

## Description
When the rsync daemon is configured with a module that exposes a path (such
as `/`) without `auth users` and without a `secrets file`, any client that can
reach port 873 can:

- **Read** any file on the exposed path (including `/etc/passwd`,
  `/etc/shadow`, SSH private keys, application secrets).
- **Write** arbitrary files anywhere under the module path (e.g., drop a
  cron job, overwrite `/etc/cron.d/`, plant SSH authorized_keys).

No credentials, no exploit, no CVE needed — the service simply has no access
control configured. A single rsync command:

```
rsync rsync://target/data/etc/passwd /tmp/stolen-passwd
```

succeeds without prompting for a password and returns the full content of
`/etc/passwd`.

## Affected Service
- **Service:** rsync daemon (any version)
- **Port:** 873/TCP
- **Vulnerable configuration:** Module in `/etc/rsyncd.conf` without
  `auth users` or `secrets file`

## Remediation Steps
1. Add `auth users` to each module:
   ```ini
   auth users = rsyncuser
   ```
2. Create a secrets file (e.g. `/etc/rsyncd.secrets`) containing
   `user:password` pairs, one per line:
   ```
   rsyncuser:StrongPassw0rd!
   ```
3. Restrict the secrets file permissions to root-readable only:
   ```
   chmod 600 /etc/rsyncd.secrets
   ```
4. Reference the secrets file in `rsyncd.conf`:
   ```ini
   secrets file = /etc/rsyncd.secrets
   ```
5. Set `use chroot = yes` and restrict the module `path` to the minimum
   necessary directory (not `/`).
6. Verify unauthenticated access is denied:
   ```
   rsync rsync://localhost/data/etc/passwd   # must prompt or refuse
   ```
7. Regression: authenticated access works:
   ```
   rsync --password-file=/etc/rsyncd.secrets rsync://rsyncuser@localhost/data/
   ```
