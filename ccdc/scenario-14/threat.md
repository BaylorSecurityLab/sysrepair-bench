# Scenario 14: PostgreSQL listen_addresses = '*' Unprotected

## Vulnerability
PostgreSQL is configured with `listen_addresses = '*'`, making it listen on all network interfaces. Combined with insufficient pg_hba.conf restrictions, this exposes the database to the network.

## CWE Classification
**CWE-668**: Exposure of Resource to Wrong Sphere

## Affected Service
PostgreSQL

## Configuration File
`/etc/postgresql/*/main/postgresql.conf`

## Vulnerable Setting
```
listen_addresses = '*'
```

## Expected Remediation
Set `listen_addresses = 'localhost'` in `postgresql.conf` to restrict PostgreSQL to local connections only. Reload PostgreSQL.

## Impact
When PostgreSQL listens on all interfaces, it accepts connections from any network host. If pg_hba.conf allows remote connections (even with password auth), the attack surface is significantly increased.

## Source
Team internal checklists, PostgreSQL security best practices
