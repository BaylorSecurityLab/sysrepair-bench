# CUPS Accepts Deprecated TLSv1.0 / TLSv1.1

## Severity
**Medium** (CVSS 5.3)

## CVE / CWE
- CWE-326: Inadequate Encryption Strength
- CVE-2011-3389 (BEAST — TLSv1.0 CBC attack)
- CVE-2015-0204 (POODLE-like downgrade vectors for TLSv1.0)
- RFC 8996 formally deprecates TLSv1.0 and TLSv1.1 (March 2021)

## Description
The CUPS printing service is configured to accept connections using the deprecated
TLSv1.0 and TLSv1.1 protocols on port 631. These protocol versions are considered
cryptographically broken:

- **TLSv1.0** is susceptible to the BEAST attack (CVE-2011-3389), which allows a
  man-in-the-middle to recover plaintext from an encrypted session using CBC-mode
  ciphers. It also cannot use modern AEAD cipher suites.
- **TLSv1.1** improves on TLSv1.0's CBC initialization vector handling but still lacks
  support for AEAD (GCM) ciphers and relies on SHA-1 in its PRF construction.
- Both versions were deprecated by RFC 8996 in 2021 and are disabled by default in
  OpenSSL 1.1.0+ and most modern TLS stacks.

Any client that can be forced to downgrade to TLSv1.0 (via a downgrade oracle) is
exposed to passive decryption and active injection attacks.

## Affected Service
- **Service:** CUPS (Common Unix Printing System)
- **Port:** 631/TCP (HTTPS)
- **Binary:** /usr/sbin/cupsd
- **Configuration:** /etc/cups/cupsd.conf

## Vulnerable Configuration

```
# /etc/cups/cupsd.conf (vulnerable)
SSLOptions AllowSSL3 AllowTLS1 AllowTLS11
```

## Remediation Steps
1. Edit `/etc/cups/cupsd.conf` and replace the `SSLOptions` line to deny deprecated
   protocol versions:
   ```
   SSLOptions None
   ```
   Alternatively, explicitly deny each deprecated version:
   ```
   SSLOptions DenySSL3 DenyTLS1 DenyTLS11
   ```
2. Restart CUPS:
   ```
   /etc/init.d/cups restart
   ```
3. Verify by attempting a TLSv1.0 connection — it must fail — and a TLSv1.2 connection
   must still succeed:
   ```
   openssl s_client -connect localhost:631 -tls1        # must fail
   openssl s_client -connect localhost:631 -tls1_2      # must succeed
   ```
