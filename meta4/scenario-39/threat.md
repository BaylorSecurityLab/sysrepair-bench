# MongoDB 4.4 — No Authentication (misconfig)

## Severity
**High** (CVSS 9.1)

## CVE / CWE
- CWE-284: Improper Access Control

## Description
MongoDB 4.4 ships with authentication disabled by default. When started with
`--bind_ip_all`, the server listens on `0.0.0.0:27017` and accepts connections
from any client on any interface without requiring credentials. An attacker
with network access to the host can connect directly using `mongosh` or the
MongoDB wire protocol and gain full read, write, and administrative control
over every database — including listing, modifying, and dropping collections
and user data.

This is a misconfiguration, not a code vulnerability, but its impact is
equivalent to a critical authentication bypass: there are no credentials to
steal and no exploit to craft. A single command such as:

```
mongosh --quiet --eval "db.adminCommand('listDatabases')"
```

succeeds without any username or password, returning a full inventory of
all hosted databases.

## Affected Service
- **Service:** MongoDB 4.4
- **Port:** 27017/TCP
- **Vulnerable configuration:** `mongod --bind_ip_all` with no `--auth` flag

## Vulnerable Configuration
- MongoDB started without `--auth`, leaving the server in unauthenticated mode
- `--bind_ip_all` (or `--bind_ip 0.0.0.0`) exposes the port to all network interfaces

## Remediation Steps
1. Start `mongod` with the `--auth` flag to require credentials for all
   connections: add `--auth` to the `CMD` or `mongod.conf` `security.authorization: enabled`.
2. Create an admin user in the `admin` database before enabling auth:
   ```
   use admin
   db.createUser({ user: "admin", pwd: "<strong-password>",
                   roles: [{ role: "userAdminAnyDatabase", db: "admin" },
                           "readWriteAnyDatabase"] })
   ```
3. Change the bind address to `127.0.0.1` (or the specific interface required)
   by replacing `--bind_ip_all` with `--bind_ip 127.0.0.1` in the startup
   command, preventing remote clients from reaching the port at all.
4. Verify that `mongosh` connects successfully with the newly created credentials:
   ```
   mongosh -u admin -p <strong-password> --authenticationDatabase admin \
       --eval "db.adminCommand('listDatabases')"
   ```
