# SSH Weak Host Key Algorithms (ssh-rsa, ssh-dss)

## Severity
**Medium** (CVSS 5.9)

## CVE / CWE
- CWE-326: Inadequate Encryption Strength
- CVE-2023-38408 (OpenSSH ssh-agent RCE — context: ssh-rsa chain of trust issues)
- RFC 8332 deprecates ssh-rsa with SHA-1; NIST SP 800-131A disallows DSA/DSS after 2015

## Description
The OpenSSH server is configured to advertise and accept deprecated host key algorithms:

- `ssh-rsa` — the traditional RSA signature scheme uses SHA-1 for the signature hash.
  SHA-1 is cryptographically broken; collision attacks are practical and chosen-prefix
  attacks have been demonstrated. A compromised or forged host key certificate signed with
  SHA-1 could be accepted by unpatched clients performing host authentication.
- `ssh-dss` — Digital Signature Algorithm with a fixed 1024-bit key size (DSA-1024).
  NIST deprecated DSA-1024 in 2011; the key space is within reach of well-funded
  adversaries. ssh-dss was removed from OpenSSH defaults in version 7.0 (2015).

When these algorithms are advertised, a client that accepts them can be manipulated
into authenticating a spoofed server, enabling man-in-the-middle attacks against the
key-exchange phase.

## Affected Service
- **Service:** OpenSSH Server
- **Port:** 22/TCP
- **Binary:** /usr/sbin/sshd
- **Configuration:** /etc/ssh/sshd_config
- **Key files:** /etc/ssh/ssh_host_dsa_key, /etc/ssh/ssh_host_dsa_key.pub

## Vulnerable Configuration

```
# /etc/ssh/sshd_config (vulnerable)
HostKeyAlgorithms +ssh-rsa,ssh-dss
HostKey /etc/ssh/ssh_host_dsa_key
```

## Remediation Steps
1. Remove or disable the DSA host key:
   ```
   rm -f /etc/ssh/ssh_host_dsa_key /etc/ssh/ssh_host_dsa_key.pub
   ```
2. Edit `/etc/ssh/sshd_config`: remove the `HostKey /etc/ssh/ssh_host_dsa_key` line and
   replace `HostKeyAlgorithms +ssh-rsa,ssh-dss` with a strict allowlist of modern
   algorithms:
   ```
   HostKeyAlgorithms rsa-sha2-512,rsa-sha2-256,ssh-ed25519
   ```
3. Restart the SSH daemon:
   ```
   /etc/init.d/ssh restart
   ```
4. Confirm by attempting a connection that forces `ssh-dss` — it must fail. A connection
   using `rsa-sha2-256` must succeed:
   ```
   ssh -oHostKeyAlgorithms=ssh-dss -p 22 localhost       # must fail
   ssh -oHostKeyAlgorithms=rsa-sha2-256 -p 22 localhost  # must succeed
   ```
