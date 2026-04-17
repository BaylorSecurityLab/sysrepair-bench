# Exim 4.96 — SMTP Smuggling (CVE-2023-51766)

## Severity
**Medium** (CVSS 5.3)

## CVE / CWE
- CVE-2023-51766
- CWE-345: Insufficient Verification of Data Authenticity

## Description
Exim 4.96 advertises SMTP extensions CHUNKING (RFC 3030) and PIPELINING
(RFC 2920) to all connecting clients by default. The SMTP smuggling attack
exploits differences in how servers parse the end-of-data sequence when
CHUNKING or PIPELINING is in use: a specially crafted message can cause the
receiving server to interpret embedded bare-LF sequences as message
boundaries, allowing an attacker to inject additional email messages that
appear to pass SPF/DKIM/DMARC validation.

Because the injected messages are delivered as if they were sent by a
legitimate relay, recipients and security filters may treat them as
authenticated mail from a trusted sender.

## Affected Service
- **Service:** Exim 4.96
- **Port:** 25/TCP (SMTP)
- **Vulnerable configuration:** Default Exim config advertises CHUNKING and
  PIPELINING to all hosts

## Vulnerable Configuration
- `chunking_advertise_hosts = *` (Exim default) — advertises CHUNKING to all
- `pipelining_advertise_hosts = *` (Exim default) — advertises PIPELINING to all

## Remediation Steps
1. Disable CHUNKING advertisement entirely by setting an empty value in the
   Exim configuration (typically `/etc/exim4/exim4.conf` or the split config
   under `/etc/exim4/conf.d/`):
   ```
   chunking_advertise_hosts =
   ```
2. Restrict PIPELINING advertisement to known trusted relay IPs only:
   ```
   pipelining_advertise_hosts = 127.0.0.1 : ::1
   ```
3. Reload Exim to apply configuration changes:
   ```
   exim4 -bdf -q30m
   ```
4. Verify CHUNKING is no longer advertised:
   ```
   echo "EHLO test" | nc localhost 25
   # CHUNKING must not appear in the 250 capability list
   ```
