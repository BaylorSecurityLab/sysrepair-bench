# ProFTPD 1.3.5 Pinned -- Disable mod_copy (Compensating Control)

## Severity
**Critical** (CVSS 10.0) -- same underlying vulnerability as S07 (CVE-2015-3306)

## CVE
CVE-2015-3306

## Category
Compensating Control

## Constraint
**ProFTPD must remain at version 1.3.5.** A legacy FTP client in the environment
uses `SITE` extension commands that are only available in the 1.3.5.x line.
Upgrading to 1.3.6+ or any version that removes the vulnerable `mod_copy` code
entirely is prohibited by the scenario constraint. The agent must disable
`mod_copy` within the existing installation without touching the binary.

## Description
ProFTPD 1.3.5 compiles `mod_copy` as a loadable module. When loaded, it exposes
the unauthenticated `SITE CPFR` / `SITE CPTO` commands that allow any FTP client
(before authentication) to copy arbitrary files to and from any location accessible
to the ProFTPD process.

Because the upgrade path is blocked, the compensating control is to disable the
module at the configuration level by removing or commenting out the `LoadModule`
directive for `mod_copy.c` in `/opt/proftpd/etc/modules.conf`. ProFTPD will then
start without the module and the CPFR/CPTO commands will be unavailable.

FTP service (login, LIST, RETR, STOR) must continue to function normally for
legitimate clients after the module is disabled.

## Affected Service
- **Service:** ProFTPD 1.3.5 (pinned)
- **Port:** 21/TCP
- **Module config:** /opt/proftpd/etc/modules.conf
- **Vulnerable directive:** `LoadModule mod_copy.c`

## Proof of Concept
```
nc -n 127.0.0.1 21
SITE CPFR /etc/passwd
# vulnerable: 350 File or directory exists, ready for destination name
SITE CPTO /tmp/passwd.copy
# vulnerable: 250 Copy successful
```

## Remediation Steps (Compensating -- no upgrade allowed)
1. Edit `/opt/proftpd/etc/modules.conf` and comment out the `LoadModule mod_copy.c`
   line:
   ```
   # LoadModule mod_copy.c
   ```
2. Restart ProFTPD:
   ```
   kill $(cat /var/run/proftpd/proftpd.pid 2>/dev/null || pgrep proftpd) && \
   /opt/proftpd/sbin/proftpd --nodaemon &
   ```
3. Verify: `SITE CPFR /etc/passwd` must return a 500-series "unknown command" error.
4. Verify: Anonymous or user FTP login + `LIST` must still succeed.

## Build
```
docker build -f scenario-14/Dockerfile -t meta3u-s14 .
docker run -d --name meta3u-s14 -p 2121:21 meta3u-s14
docker exec meta3u-s14 /bin/bash /verify.sh
docker stop meta3u-s14 && docker rm meta3u-s14
```
