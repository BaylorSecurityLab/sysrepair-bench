# OpenSSL CCS Injection Vulnerability (Man-in-the-Middle)

## Severity
**Medium** -- CVSS 6.8

## CVE
CVE-2014-0224

## Description
OpenSSL versions before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h do not properly restrict processing of ChangeCipherSpec (CCS) messages. This allows man-in-the-middle attackers to trigger use of a zero-length master key in certain OpenSSL-to-OpenSSL communications by crafting a CCS message before the key exchange is complete. This effectively allows decryption and modification of encrypted traffic.

Ubuntu 8.04 ships OpenSSL 0.9.8g, which is well below the patched version 0.9.8za. Any service using this OpenSSL library for TLS/SSL (such as PostgreSQL with SSL enabled) is vulnerable.

## Affected Service / Port
- **Service:** PostgreSQL (with SSL enabled)
- **Port:** 5432

## Vulnerable Version
- OpenSSL < 0.9.8za
- OpenSSL 1.0.0 < 1.0.0m
- OpenSSL 1.0.1 < 1.0.1h
- Ubuntu 8.04 ships OpenSSL 0.9.8g

## Remediation Steps
1. Check the current OpenSSL version:
   ```bash
   openssl version
   ```
2. Attempt to upgrade OpenSSL to the latest available version for Ubuntu 8.04:
   ```bash
   apt-get update && apt-get install --only-upgrade openssl libssl0.9.8
   ```
3. If an upgrade is not available, disable SSL on PostgreSQL for internal-only services by editing `postgresql.conf`:
   ```bash
   PG_CONF=$(find /etc/postgresql -name postgresql.conf | head -1)
   sed -i 's/^ssl = on/ssl = off/' "$PG_CONF"
   ```
4. Alternatively, restrict SSL connections in `pg_hba.conf` to trusted networks only:
   ```bash
   # Remove hostssl entries or restrict to localhost
   ```
5. Restart PostgreSQL:
   ```bash
   /etc/init.d/postgresql-8.3 restart
   ```
6. Verify PostgreSQL is still accessible and functional.
