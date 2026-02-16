# SSH Weak MAC Algorithms

## Severity
**Low** (CVSS 2.6)

## CVE
N/A (configuration weakness)

## Description
The OpenSSH server on this system is configured to allow weak Message Authentication Code
(MAC) algorithms. The default configuration of OpenSSH on Ubuntu 8.04 enables MAC algorithms
that are considered cryptographically weak:

- **hmac-md5** and **hmac-md5-96**: MD5-based MACs are vulnerable to collision attacks.
  While not directly exploitable for SSH integrity in most cases, using MD5 violates
  modern security standards and compliance requirements.
- **hmac-sha1-96**: A truncated SHA-1 MAC that provides only 96 bits of output, reducing
  the security margin below recommended levels.

These weak MACs could theoretically allow an attacker to tamper with SSH traffic without
detection in specific attack scenarios, particularly if combined with other vulnerabilities.

## Affected Service
- **Service:** OpenSSH Server
- **Port:** 22/TCP
- **Binary:** /usr/sbin/sshd
- **Configuration:** /etc/ssh/sshd_config

## Vulnerable Configuration
The default `/etc/ssh/sshd_config` does not contain a `MACs` directive, which causes sshd
to accept all compiled-in MAC algorithms, including the weak ones:

```
# No MACs line present — all defaults enabled:
# hmac-md5,hmac-sha1,hmac-ripemd160,hmac-sha1-96,hmac-md5-96,
# umac-64@openssh.com
```

## Remediation Steps
1. Edit `/etc/ssh/sshd_config` and add or modify the `MACs` directive to only allow
   the strongest available MAC on this system:
   ```
   MACs hmac-sha1
   ```
   Note: On Ubuntu 8.04's OpenSSH version, hmac-sha1 is the strongest full-length MAC
   available. hmac-ripemd160 is also acceptable as a secondary option.
2. Restart the SSH daemon:
   ```
   /etc/init.d/ssh restart
   ```
3. Verify the change by connecting with `ssh -vv` and confirming only approved MACs are
   offered.
