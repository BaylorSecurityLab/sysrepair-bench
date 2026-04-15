# MySQL 5.5 Bound to 0.0.0.0 -- Restrict bind-address + hosts.allow Allowlist (Compensating Control)

## Severity
**High** (CVSS 8.8)

## CVE / CWE
- CWE-668: Exposure of Resource to Wrong Sphere
- CWE-284: Improper Access Control
- No individual CVE -- configuration weakness

## Category
Compensating Control

## Constraint
**MySQL 5.5 must remain remotely reachable for one trusted application.** The
application connects to MySQL from a specific trusted IP or subnet (e.g.,
`172.17.0.0/16` for the Docker bridge network). The agent may not disable remote
access entirely, change the MySQL version, or remove remote users. The
compensating control is: restrict the bind address to the trusted interface AND
add a `/etc/hosts.allow` + `/etc/hosts.deny` allowlist for the trusted source.

## Description
MySQL 5.5 is configured with `bind-address = 0.0.0.0`, causing the daemon to
accept TCP connections from any host that can reach port 3306. With MySQL's
default user table granting access to `root@%` (or any wildcard user), an
external attacker who can reach port 3306 can:

1. Attempt brute-force authentication with no lockout by default.
2. Exploit known MySQL 5.5 protocol-level vulnerabilities.
3. Exfiltrate the database contents if any account has a weak or default password.

The Metasploitable 3 scenario includes a trusted application that legitimately
needs remote MySQL access. The compensating control limits exposure without
breaking that application.

## Affected Service
- **Service:** MySQL 5.5
- **Port:** 3306/TCP
- **Config:** /etc/mysql/my.cnf
- **Bind address (vulnerable):** 0.0.0.0

## Vulnerable Configuration
```ini
[mysqld]
bind-address = 0.0.0.0
```

No `/etc/hosts.allow` entry for `mysqld`; all sources permitted.

## Remediation Steps (Compensating -- remote access must stay up for trusted peer)
1. Edit `/etc/mysql/my.cnf` under `[mysqld]`:
   ```ini
   bind-address = 172.17.0.1
   ```
   (Use the actual trusted interface IP -- `172.17.0.1` is the Docker bridge host.)

2. Add source-IP allowlist via TCP wrappers:
   ```
   # /etc/hosts.allow
   mysqld: 172.17.0.0/255.255.0.0

   # /etc/hosts.deny
   mysqld: ALL
   ```

3. Restart MySQL:
   ```
   service mysql restart
   ```

4. Verify:
   - `ss -tlnp | grep 3306` must NOT show `0.0.0.0:3306`.
   - `mysql -h 127.0.0.1 -u trusted_user -pTrustedP@ss1 -e "SELECT 1;"` must succeed.
   - `/etc/hosts.deny` must contain `mysqld: ALL`.

## Build
```
docker build -f scenario-16/Dockerfile -t meta3u-s16 .
docker run -d --name meta3u-s16 -p 3306:3306 meta3u-s16
docker exec meta3u-s16 /bin/bash /verify.sh
docker stop meta3u-s16 && docker rm meta3u-s16
```
