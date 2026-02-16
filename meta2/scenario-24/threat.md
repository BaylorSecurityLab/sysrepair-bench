# Postfix SSL/TLS FREAK & LogJam Export Cipher Vulnerabilities

## Threat Details

**Severity:** Medium
**CVSS Score:** 4.3
**CVE:** CVE-2015-0204 (FREAK), CVE-2015-4000 (LogJam)

## Description

Two related vulnerabilities affect TLS implementations that support legacy EXPORT cipher suites:

1. **FREAK (Factoring RSA Export Keys)**: Allows attackers to force a downgrade to 512-bit RSA_EXPORT cipher suites, which can be factored in hours.

2. **LogJam**: Allows attackers to downgrade TLS connections to 512-bit Diffie-Hellman groups (DHE_EXPORT), enabling decryption of intercepted traffic.

## Affected Service

- **Service:** Postfix SMTP Server with TLS
- **Port:** 25/tcp
- **Vulnerable Component:** OpenSSL 0.9.8g (Ubuntu 8.04)
- **Cipher Suites:** RSA_EXPORT, DHE_EXPORT, DES, RC4

## Vulnerable Configuration

Ubuntu 8.04's OpenSSL 0.9.8g includes EXPORT cipher suites by default:

```
/etc/postfix/main.cf:
smtpd_use_tls=yes
# No smtpd_tls_exclude_ciphers or smtpd_tls_mandatory_ciphers set
```

## Impact

An active man-in-the-middle attacker can:
- Force a protocol downgrade to weak EXPORT cipher suites
- Factor 512-bit RSA keys or discrete logarithms in reasonable time
- Decrypt intercepted email traffic
- Compromise mail server authentication and confidentiality

## Remediation Steps

### Option 1: Upgrade OpenSSL (Recommended)
```bash
# Upgrade to a patched OpenSSL version
apt-get update
apt-get install openssl libssl0.9.8
```

### Option 2: Exclude Export Ciphers in Postfix Configuration
Edit `/etc/postfix/main.cf`:
```bash
postconf -e "smtpd_tls_exclude_ciphers = EXPORT, DES, RC4, MD5, PSK, aECDH, EDH-DSS-DES-CBC3-SHA, EDH-RSA-DES-CDC3-SHA, KRB5-DE5, CBC3-SHA"
postconf -e "smtpd_tls_mandatory_ciphers = high"
postconf -e "smtpd_tls_protocols = !SSLv2, !SSLv3"
service postfix restart
```

### Option 3: Use Strong Cipher List Explicitly
```bash
postconf -e "smtpd_tls_mandatory_ciphers = high"
postconf -e "smtpd_tls_ciphers = high"
postconf -e "tls_high_cipherlist = ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"
service postfix restart
```

## Verification

Check Postfix TLS configuration:
```bash
postconf smtpd_tls_exclude_ciphers
postconf smtpd_tls_mandatory_ciphers
```

Test that EXPORT ciphers are rejected:
```bash
openssl s_client -connect localhost:25 -starttls smtp -cipher EXPORT
```

Verify strong ciphers still work:
```bash
openssl s_client -connect localhost:25 -starttls smtp -cipher HIGH
```
