# SSH Weak Key Exchange (KEX) Algorithms

## Severity
**Medium** (CVSS 5.9)

## CVE / CWE
- CWE-326: Inadequate Encryption Strength
- CVE-2015-4000 (Logjam — affects diffie-hellman-group1-sha1 / 768-1024-bit DH)

## Description
The OpenSSH server is configured to advertise and accept SHA1-based Diffie-Hellman
key exchange algorithms. The affected algorithms are:

- `diffie-hellman-group1-sha1` — uses a fixed 1024-bit Oakley Group 1 prime, deprecated
  by RFC 8270 and directly vulnerable to the Logjam attack (CVE-2015-4000). A
  nation-state adversary capable of pre-computing discrete logarithms for this group can
  perform a downgrade and decrypt or modify the session in real time.
- `diffie-hellman-group14-sha1` — uses a 2048-bit prime but pairs it with SHA-1 for key
  derivation. SHA-1 is considered cryptographically broken (NIST deprecated it for
  digital signatures in 2011).
- `diffie-hellman-group-exchange-sha1` — allows negotiated DH group exchange but hashes
  the shared secret with SHA-1, carrying the same weakness.

An attacker positioned on the network path can force a downgrade to the weakest
advertised algorithm and, depending on resources, recover session keys.

## Affected Service
- **Service:** OpenSSH Server
- **Port:** 22/TCP
- **Binary:** /usr/sbin/sshd
- **Configuration:** /etc/ssh/sshd_config

## Vulnerable Configuration

```
# /etc/ssh/sshd_config (vulnerable)
KexAlgorithms diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1
```

## Remediation Steps
1. Edit `/etc/ssh/sshd_config` and replace the `KexAlgorithms` line with modern
   elliptic-curve and SHA-256-based algorithms only:
   ```
   KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
   ```
2. Restart the SSH daemon:
   ```
   /etc/init.d/ssh restart
   ```
3. Confirm the change by running `ssh -Q kex` on the server and verifying that no
   SHA1-based method is listed, then attempt a connection using only the old algorithm
   to confirm rejection:
   ```
   ssh -oKexAlgorithms=diffie-hellman-group1-sha1 -p 22 localhost
   ```
   The connection must be refused. A connection using default (modern) KEX must still
   succeed.
