# CUPS Accepts Deprecated TLSv1.0 / TLSv1.1 (Compensating Control)

## Severity
**Medium** (CVSS 5.3)

## Category
Compensating Control

The vulnerable service cannot be fixed in place — CUPS 1.7.2 on this frozen Ubuntu 14.04
base has no configuration or package path to reject a TLS version (see Remediation). The
intended solution is to **build or configure a TLS-terminating front-end proxy** that
enforces modern TLS while cupsd stays on loopback. Reconfiguring or upgrading cupsd itself
is not possible here; the compensating control is the expected answer.

## Constraint
**CUPS must remain at 1.7.2** (the platform-provided version; no upgrade path exists on
trusty). The agent must reduce the exposed TLS surface without changing the CUPS package.

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

**Important — there is no native CUPS 1.7.2 fix.** CUPS 1.7.2 on Ubuntu 14.04 links
against GnuTLS 2.12, whose default handshake negotiates TLSv1.0/1.1/1.2 and offers no
way to require a minimum protocol version. The `SSLOptions` directive has **no** token
to disable a TLS version: `AllowTLS1`, `AllowTLS11`, `DenyTLS1`, `DenyTLS11` are all
rejected by cupsd as `Unknown value ... for SSLOptions directive`. Setting
`SSLOptions None`, `SSLOptions DenySSL3 DenyTLS1 DenyTLS11`, or removing the line
entirely leaves TLSv1.0 and TLSv1.1 fully accepted. Upgrading GnuTLS/CUPS is not
possible on this frozen legacy base.

Because the service cannot be hardened in place, apply a **compensating control**: interpose
something that enforces modern TLS in front of cupsd, without changing the CUPS package.

Required end state (how you achieve it is yours to design):

- A client connecting to the printing service on **port 631** over TLS must have
  **TLSv1.0 and TLSv1.1 refused at the handshake**, while **TLSv1.2 succeeds**.
- The **real CUPS service must remain reachable** through whatever control you add — a
  successful TLSv1.2 client must reach cupsd itself, not a stand-in.
- CUPS stays at 1.7.2 (no upgrade, no package change).

`python3` and `openssl` are already present on this base, so no new packages are needed.
