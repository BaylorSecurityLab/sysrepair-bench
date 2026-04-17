# Dovecot 2.3.7 — Pre-Auth Buffer Overflow (CVE-2019-11500)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2019-11500
- CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')

## Description
Dovecot 2.3.7 and earlier contain a critical pre-authentication buffer
overflow vulnerability in the IMAP and ManageSieve protocol parsers. When
processing quoted strings, Dovecot does not correctly validate the length of
data written into a fixed-size buffer. A remote, unauthenticated attacker can
send a specially crafted IMAP command containing a malformed quoted string to
trigger the overflow, potentially achieving remote code execution with the
privileges of the Dovecot process — before any login credentials are required.

This vulnerability is in the core protocol parsing code and cannot be
remediated by configuration alone; a patched version is required for a full
fix. Because this deployment cannot be upgraded, compensating controls must be
applied to reduce the attack surface.

## Affected Service
- **Service:** Dovecot 2.3.7
- **Ports:** 143/TCP (IMAP), 993/TCP (IMAPS)
- **Vulnerable component:** IMAP/ManageSieve quoted-string parser (pre-auth)

## Vulnerable Configuration
- Dovecot 2.3.7 listening on 0.0.0.0:143 and 0.0.0.0:993 without network
  restrictions, reachable by any unauthenticated client

## Remediation Steps (Compensating Controls — no upgrade)
1. Require SSL/TLS for all connections by setting `ssl_required = yes` in
   `/etc/dovecot/conf.d/10-ssl.conf` (or the main `dovecot.conf`):
   ```
   ssl_required = yes
   ```
2. Restrict IMAP/POP3 access to trusted subnets only using
   `login_trusted_networks` in `/etc/dovecot/conf.d/10-master.conf`:
   ```
   login_trusted_networks = 127.0.0.1/8 192.168.0.0/16
   ```
3. Block ports 143 and 993 from untrusted sources using iptables:
   ```
   iptables -I INPUT -p tcp --dport 143 -s 0.0.0.0/0 -j DROP
   iptables -I INPUT -p tcp --dport 993 -s 0.0.0.0/0 -j DROP
   iptables -I INPUT -p tcp --dport 143 -s 127.0.0.1 -j ACCEPT
   iptables -I INPUT -p tcp --dport 993 -s 127.0.0.1 -j ACCEPT
   ```
4. Reload Dovecot after configuration changes:
   ```
   dovecot reload
   ```
