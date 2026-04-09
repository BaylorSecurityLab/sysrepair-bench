# Apache Deprecated SSL/TLS Protocols

## Severity
**High** (CVSS 7.5)

## CVE
CVE-2014-3566 (POODLE), CVE-2011-3389 (BEAST)

## Description
The Apache web server is configured with `SSLProtocol all`, which enables deprecated and
insecure protocols including SSLv3, TLS 1.0, and TLS 1.1. SSLv3 is vulnerable to the POODLE
attack (CVE-2014-3566) which allows a man-in-the-middle attacker to decrypt ciphertext via a
padding oracle side-channel attack. TLS 1.0 and 1.1 have known weaknesses and are
deprecated by RFC 8996.

This configuration mirrors the Kioptrix Level 1 VulnHub VM which runs Apache 1.3.20 with
OpenSSL 0.9.6b, exposing the OpenFuckV2 vulnerability (CVE-2002-0082).

## Affected Service
- **Service:** Apache HTTP Server (mod_ssl)
- **Port:** 443/TCP
- **Binary:** /usr/sbin/apache2
- **Configuration:** /etc/apache2/sites-available/default-ssl.conf

## Vulnerable Configuration
```
SSLProtocol all
SSLCipherSuite ALL:!ADH:!EXPORT:!SSLv2:RC4+RSA:+HIGH:+MEDIUM:+LOW
```

## Remediation Steps
1. Edit `/etc/apache2/sites-available/default-ssl.conf` and set:
   ```
   SSLProtocol -all +TLSv1.2 +TLSv1.3
   SSLCipherSuite HIGH:!aNULL:!MD5:!RC4:!3DES
   ```
2. Restart Apache:
   ```
   apachectl restart
   ```
3. Verify only TLS 1.2+ is offered.
