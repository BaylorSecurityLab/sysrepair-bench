# OpenSSH Terrapin Prefix-Truncation Attack (CVE-2023-48795)

## Severity
**Medium** (CVSS 5.9)

## CVE / CWE
- CVE-2023-48795
- CWE-354: Improper Validation of Integrity Check Value

## Description
The SSH Binary Packet Protocol (BPP) is vulnerable to a novel
prefix-truncation attack dubbed "Terrapin." An active
man-in-the-middle attacker can delete consecutive messages at the
beginning of the encrypted channel without the endpoints detecting the
manipulation. This effectively strips security-critical handshake
messages such as the `EXT_INFO` extension negotiation, downgrading the
connection's security guarantees.

The attack is possible when the connection uses **ChaCha20-Poly1305**
or any **CBC cipher paired with Encrypt-then-MAC (EtM)** MACs. These
modes use a sequence-number-dependent approach that allows the
attacker to adjust counters after deletion.

## Affected Service
- **Service:** OpenSSH (sshd)
- **Port:** 22/TCP
- **Config:** `/etc/ssh/sshd_config`
- **Vulnerable ciphers:** `chacha20-poly1305@openssh.com`
- **Vulnerable MACs:** any `*-etm@openssh.com` variant

## Remediation Steps
1. Edit `/etc/ssh/sshd_config` to set `Ciphers` excluding
   `chacha20-poly1305@openssh.com` and any CBC ciphers. Use only
   CTR or GCM ciphers, e.g.:
   `Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com`
2. Set `MACs` excluding all `*-etm@openssh.com` variants. Use only
   non-EtM MACs, e.g.:
   `MACs hmac-sha2-256,hmac-sha2-512`
3. Reload or restart sshd: `systemctl reload sshd` or
   `kill -HUP $(cat /run/sshd.pid)` or restart the service.
4. Regression: sshd must still accept SSH connections on port 22.
