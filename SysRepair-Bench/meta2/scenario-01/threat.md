# SSH Weak Encryption Algorithms

## Severity
**Medium** (CVSS 4.3)

## CVE
N/A (configuration weakness)

## Description
The OpenSSH server on this system is configured to allow weak and deprecated encryption
algorithms. The default configuration of OpenSSH on Ubuntu 8.04 enables CBC-mode ciphers
(3des-cbc, blowfish-cbc, cast128-cbc, aes128-cbc, aes192-cbc, aes256-cbc) and RC4-based
ciphers (arcfour, arcfour128, arcfour256). These algorithms are vulnerable to known
cryptographic attacks:

- **CBC ciphers** are susceptible to the CPNI-957037 plaintext recovery attack, which can
  allow an attacker to recover up to 32 bits of plaintext from an arbitrary block of
  ciphertext from a connection secured using the SSH protocol.
- **RC4/arcfour** ciphers have known statistical biases that weaken confidentiality.

An attacker performing a man-in-the-middle attack could exploit these weaknesses to
partially decrypt SSH traffic.

## Affected Service
- **Service:** OpenSSH Server
- **Port:** 22/TCP
- **Binary:** /usr/sbin/sshd
- **Configuration:** /etc/ssh/sshd_config

## Vulnerable Configuration
The default `/etc/ssh/sshd_config` does not contain a `Ciphers` directive, which causes
sshd to accept all compiled-in ciphers, including the weak ones:

```
# No Ciphers line present — all defaults enabled:
# aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,arcfour128,arcfour256,arcfour,
# aes192-cbc,aes256-cbc,aes128-ctr,aes192-ctr,aes256-ctr
```

## Remediation Steps
1. Edit `/etc/ssh/sshd_config` and add or modify the `Ciphers` directive to only allow
   CTR-mode ciphers:
   ```
   Ciphers aes256-ctr,aes192-ctr,aes128-ctr
   ```
2. Restart the SSH daemon:
   ```
   /etc/init.d/ssh restart
   ```
3. Verify the change by connecting with `ssh -vv` and confirming only CTR ciphers are
   offered.
