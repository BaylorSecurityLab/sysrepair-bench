# PostgreSQL SSLv3 Protocol POODLE Vulnerability

## Threat Details

**Severity:** Medium
**CVSS Score:** 4.3
**CVE:** CVE-2014-3566

## Description

The POODLE (Padding Oracle On Downgraded Legacy Encryption) vulnerability affects SSLv3 protocol CBC cipher suites. PostgreSQL compiled against vulnerable OpenSSL versions (< 0.9.8za, < 1.0.0m, < 1.0.1h) allows SSLv3 connections, enabling attackers to decrypt encrypted traffic through a padding oracle attack.

## Affected Service

- **Service:** PostgreSQL Database Server
- **Port:** 5432/tcp
- **Vulnerable Component:** OpenSSL 0.9.8g (Ubuntu 8.04)
- **Protocol:** SSLv3

## Vulnerable Configuration

Ubuntu 8.04 ships with OpenSSL 0.9.8g which enables SSLv3 protocol by default. When PostgreSQL is configured with `ssl = on`, it inherits this vulnerability:

```
/etc/postgresql/8.3/main/postgresql.conf:
ssl = on
```

## Impact

An attacker positioned as a man-in-the-middle can:
- Force a protocol downgrade to SSLv3
- Exploit the CBC padding oracle to decrypt traffic
- Extract sensitive data from PostgreSQL connections (credentials, query data)
- Compromise database security even with encryption enabled

## Remediation Steps

### Option 1: Upgrade OpenSSL (Recommended)
```bash
# Upgrade OpenSSL to a patched version that disables SSLv3
apt-get update
apt-get install openssl libssl0.9.8
```

### Option 2: Disable SSLv3 in PostgreSQL (If OpenSSL Cannot Be Upgraded)
Edit `/etc/postgresql/8.3/main/postgresql.conf`:
```
ssl_ciphers = 'HIGH:MEDIUM:+3DES:!aNULL:!SSLv3'
```

Or for newer PostgreSQL versions (9.4+):
```
ssl_min_protocol_version = 'TLSv1'
```

### Option 3: Disable SSL on Internal/Trusted Networks
If PostgreSQL is on a trusted network:
```bash
# Edit /etc/postgresql/8.3/main/postgresql.conf
ssl = off
service postgresql restart
```

## Verification

Check OpenSSL version:
```bash
openssl version
```

Test SSLv3 connection (should fail after remediation):
```bash
openssl s_client -connect localhost:5432 -ssl3
```

Verify TLS connections still work:
```bash
openssl s_client -connect localhost:5432 -tls1
```
