# IPMI — Cipher-Zero Authentication Bypass (protocol design flaw)

## Severity
**Critical** (CVSS 10.0)

## CVE / CWE
- CWE-306: Missing Authentication for Critical Function
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm

## Category
Compensating Controls

## Description
The Intelligent Platform Management Interface (IPMI) is a hardware-level
management protocol used for out-of-band server control (power, console,
sensors). IPMI 2.0 introduced RAKP authentication, but **cipher suite 0
(null cipher) was included as a mandatory implementation requirement**, allowing
any client to authenticate with any username and any password — the credentials
are never verified.

When UDP port 623 is exposed on `0.0.0.0`, any network-adjacent attacker can:
- Log in to the BMC as administrator using cipher 0 with any password
- Power off, reset, or PXE-boot the host
- Read/write arbitrary memory via the BMC's hardware access
- Exfiltrate IPMI credential hashes for offline cracking (RAKP hash leak)

This affects virtually all server BMCs shipped before ~2015 (Dell iDRAC,
HP iLO, Supermicro IPMI, etc.). Cipher 0 cannot be removed without breaking
the IPMI 2.0 spec — compensating controls are mandatory.

## Affected Service
- **Service:** IPMI BMC (simulated)
- **Port:** 623/UDP
- **Vulnerable configuration:** cipher_suite_ids includes 0, bound to 0.0.0.0

## Remediation Steps
1. Apply iptables to restrict UDP 623 to the management VLAN only:
   ```
   iptables -A INPUT -p udp --dport 623 -s <mgmt-vlan-cidr> -j ACCEPT
   iptables -A INPUT -p udp --dport 623 -j DROP
   ```
2. Remove cipher suite 0 from `/etc/ipmi.conf`:
   ```
   cipher_suite_ids = 3,17
   ```
3. Place BMC management ports on a dedicated out-of-band management network
   with no connectivity to production or internet networks.
4. Require strong RAKP cipher suites (17 = AES-128 + HMAC-SHA256) only.
