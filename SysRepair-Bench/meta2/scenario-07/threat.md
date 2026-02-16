# PostgreSQL Weak Password

## Severity
**High** (CVSS 9.0)

## CVE
N/A (configuration weakness / weak credentials)

## Description
The PostgreSQL database server on this system is configured with a trivially weak password
for the `postgres` superuser account. The password is set to "postgres" (same as the
username), making it trivially guessable via brute-force or dictionary attacks.

Additionally, the server is configured to:
- **Listen on all interfaces** (`listen_addresses = '*'`), exposing the database to the
  entire network.
- **Accept remote MD5-authenticated connections** from any IP address via `pg_hba.conf`,
  allowing remote attackers to attempt password-based authentication.

This configuration replicates the Metasploitable 2 PostgreSQL setup. An attacker with
network access to port 5432 can connect as the `postgres` superuser, gaining full control
over all databases and the ability to:

- Read, modify, or delete any data in any database.
- Create new superuser accounts.
- Execute arbitrary OS commands via `COPY ... TO PROGRAM` or custom functions.
- Read and write files on the server filesystem.

## Affected Service
- **Service:** PostgreSQL 8.3
- **Port:** 5432/TCP
- **Binary:** /usr/lib/postgresql/8.3/bin/postgres
- **Configuration:** /etc/postgresql/8.3/main/postgresql.conf, /etc/postgresql/8.3/main/pg_hba.conf

## Vulnerable Configuration
```
# /etc/postgresql/8.3/main/postgresql.conf
listen_addresses = '*'

# /etc/postgresql/8.3/main/pg_hba.conf
host    all    all    0.0.0.0/0    md5

# postgres user password = "postgres"
```

## Remediation Steps
1. Change the postgres user password to a strong value:
   ```
   su - postgres -c "psql -c \"ALTER USER postgres WITH PASSWORD 'NewStr0ngP@ssw0rd!';\""
   ```
2. Restrict PostgreSQL to listen only on localhost in `/etc/postgresql/8.3/main/postgresql.conf`:
   ```
   listen_addresses = 'localhost'
   ```
3. Remove or restrict the remote access line in `/etc/postgresql/8.3/main/pg_hba.conf`:
   ```
   # Remove or comment out:
   # host    all    all    0.0.0.0/0    md5
   # Replace with local-only access if needed:
   host    all    all    127.0.0.1/32    md5
   ```
4. Restart PostgreSQL:
   ```
   /etc/init.d/postgresql-8.3 restart
   ```
