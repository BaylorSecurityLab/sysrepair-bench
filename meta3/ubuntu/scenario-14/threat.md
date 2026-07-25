# ProFTPD 1.3.5 Pinned -- Disable mod_copy (Compensating Control)

## Severity
**Critical** (CVSS 10.0) -- same underlying vulnerability as S07 (CVE-2015-3306)

## CVE
CVE-2015-3306

## Category
Compensating Control

## Constraint
**ProFTPD must remain at version 1.3.5a.** A legacy FTP client in the environment uses
`SITE` extension commands from the 1.3.5.x line, so upgrading out of it is prohibited by the
scenario constraint. `mod_copy` is **statically compiled into this build** (there is no
`mod_dso`), so it cannot be disabled by editing `LoadModule` — the agent must disable it
through the module's own runtime configuration.

## Description
This build ships **ProFTPD 1.3.5a**, which already fixed the *unauthenticated* form of
CVE-2015-3306 — a pre-auth `SITE CPFR` now returns `530 Please login with USER and PASS`.
The residual exposure is that an **authenticated** user can still use `SITE CPFR`/`SITE CPTO`
to copy arbitrary files readable/writable by the ProFTPD process, outside their own
directory. Because `mod_copy` is statically linked, the fix is `mod_copy`'s own directive:

```
<IfModule mod_copy.c>
    CopyEngine off
</IfModule>
```

placed in `/opt/proftpd/etc/proftpd.conf`. With `CopyEngine off`, the `SITE CPFR`/`CPTO`
commands are rejected. FTP service (login, LIST, RETR, STOR) must continue to work for
legitimate clients.

## Affected Service
- **Service:** ProFTPD 1.3.5a (pinned; `mod_copy` statically compiled)
- **Port:** 21/TCP
- **Config:** /opt/proftpd/etc/proftpd.conf
- **Vulnerable capability:** authenticated `SITE CPFR` / `SITE CPTO` (CopyEngine on)

## Proof of Concept (authenticated)
```
# pre-auth is already blocked on 1.3.5a: SITE CPFR -> 530
# authenticate first, then:
SITE CPFR /etc/passwd
# vulnerable: 350 File or directory exists, ready for destination name
SITE CPTO /tmp/passwd.copy
# vulnerable: 250 Copy successful
```

## Remediation Steps (Compensating -- no upgrade allowed)
1. Disable the copy engine in `/opt/proftpd/etc/proftpd.conf` (do NOT touch `LoadModule` —
   `mod_copy` is static and that directive is inert here):
   ```
   <IfModule mod_copy.c>
       CopyEngine off
   </IfModule>
   ```
2. Restart ProFTPD so the running daemon reloads config (it does not re-read config per
   connection for this setting):
   ```
   kill $(cat /var/run/proftpd/proftpd.pid 2>/dev/null || pgrep proftpd) && \
   /opt/proftpd/sbin/proftpd
   ```
3. Verify: after authenticating, `SITE CPFR /etc/passwd` must return a 500-series error.
4. Verify: user FTP login + `LIST` must still succeed.

## Build
```
docker build -f scenario-14/Dockerfile -t meta3u-s14 .
docker run -d --name meta3u-s14 -p 2121:21 meta3u-s14
docker exec meta3u-s14 /bin/bash /verify.sh
docker stop meta3u-s14 && docker rm meta3u-s14
```
