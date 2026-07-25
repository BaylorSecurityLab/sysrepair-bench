# CUPS HTTPS Exposes Vulnerable Cipher Suites (SWEET32 3DES, RC4) (Compensating Control)

## Severity
**High** (CVSS 7.5)

## Category
Compensating Control

RC4 is config-toggleable on CUPS 1.7.2 (`SSLOptions AllowRC4`), but **3DES (DES-CBC3-SHA)
cannot be disabled** — CUPS 1.7.2 / GnuTLS 2.12 offers no cipher-list control, and GnuTLS
2.12 cannot even offer AES-GCM. So the service cannot be fully hardened in place. The
intended solution is to **build or configure a TLS-terminating front-end proxy** that
enforces a strong cipher suite (no RC4, no 3DES) while cupsd stays on loopback. Reconfiguring
or upgrading cupsd itself cannot remove 3DES here; the compensating control is the expected
answer.

## Constraint
**CUPS must remain at 1.7.2** (the platform-provided version; no upgrade path exists on
trusty). The agent must eliminate the weak cipher exposure without changing the CUPS package.

## CVE / CWE
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm
- CVE-2016-2183 (SWEET32 — birthday attack on 64-bit block ciphers, affects 3DES-CBC)
- CVE-2015-2808 (RC4 NOMORE — plaintext recovery from RC4 streams)
- CVE-2013-2566 (RC4 statistical biases allowing session key recovery)

## Description
The CUPS printing service HTTPS endpoint on port 631 is configured to allow cipher suites
that use the RC4 stream cipher and 3DES block cipher:

- **RC4 (AllowRC4):** RC4 is a stream cipher with well-documented statistical biases.
  The RC4 NOMORE attack (CVE-2015-2808) can recover HTTP session cookies from long-lived
  TLS connections. IETF RFC 7465 prohibits RC4 in TLS. NIST removed RC4 from approved
  algorithms in 2015.
- **3DES / SWEET32 (implicit in AllowDH with default cipher lists):** 3DES-CBC uses a
  64-bit block size. The SWEET32 attack (CVE-2016-2183) exploits birthday-bound
  collisions: after approximately 2^32 blocks (~785 GB) an attacker can recover XOR of
  two plaintext blocks, enabling cookie injection or session hijacking against long-lived
  HTTPS connections such as the CUPS web admin interface.
- **Anonymous DH (AllowDH without authentication):** Cipher suites with anonymous
  Diffie-Hellman provide no server authentication, enabling trivial man-in-the-middle
  attacks. These suites have been prohibited by RFC 4346 since 2006.

## Affected Service
- **Service:** CUPS (Common Unix Printing System)
- **Port:** 631/TCP (HTTPS)
- **Binary:** /usr/sbin/cupsd
- **Configuration:** /etc/cups/cupsd.conf

## Vulnerable Configuration

```
# /etc/cups/cupsd.conf (vulnerable)
SSLOptions AllowRC4 AllowDH
```

## Remediation Steps

**Important — there is no complete native CUPS 1.7.2 fix.** RC4 is genuinely
config-toggleable on this version (`SSLOptions AllowRC4` is a real Ubuntu POODLE-patch
token), but **3DES is not**: CUPS 1.7.2 has no `SSLOptions` token to disable 3DES and
no `SSLCipherList` directive (`DenyRC4`/`DenyDH` are rejected as `Unknown value`).
Worse, the GnuTLS 2.12 cipher set that ships with this base predates AES-GCM, so cupsd
itself cannot offer a modern AEAD suite even after every config tweak — a client
offering `AES256-GCM-SHA384` to raw cupsd is refused. No config change can both reject
3DES and serve a modern cipher.

Because the service cannot be hardened in place, apply a **compensating control**: interpose
something that enforces a strong cipher suite in front of cupsd, without changing the CUPS
package.

Required end state (how you achieve it is yours to design):

- A client connecting to the printing service on **port 631** over TLS must have
  **RC4 and 3DES (DES-CBC3-SHA) refused at the handshake**, while a **modern AEAD suite
  (e.g. AES-GCM) succeeds**.
- The **real CUPS service must remain reachable** through whatever control you add — a
  successful modern-cipher client must reach cupsd itself, not a stand-in.
- CUPS stays at 1.7.2 (no upgrade, no package change).

`python3` and `openssl` are already present on this base, so no new packages are needed.
(Note: cupsd's own GnuTLS 2.12 cannot offer AES-GCM at all, so the modern suite must come
from whatever you place in front of it.)
