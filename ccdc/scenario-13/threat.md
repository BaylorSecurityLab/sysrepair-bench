# Scenario 13: PostgreSQL pg_hba.conf Trust All Connections

## Vulnerability
PostgreSQL's `pg_hba.conf` is configured to use `trust` authentication for all connections (local and remote). This means any user can connect to any database without providing a password.

## CWE Classification
**CWE-284**: Improper Access Control

## Affected Service
PostgreSQL

## Configuration File
`/etc/postgresql/*/main/pg_hba.conf`

## Vulnerable Settings
```
local   all   all                 trust
host    all   all   0.0.0.0/0     trust
host    all   all   ::0/0         trust
```

## Expected Remediation
Change authentication method from `trust` to `md5` or `scram-sha-256` for all connections. Restrict host connections to specific IP ranges. Reload PostgreSQL.

```
local   all   all                 scram-sha-256
host    all   all   127.0.0.1/32  scram-sha-256
host    all   all   ::1/128       scram-sha-256
```

## Impact
Any user on the network can connect to PostgreSQL as any user (including superuser) without authentication, allowing full database access.

## Source
Team internal checklists, general PostgreSQL hardening best practices
