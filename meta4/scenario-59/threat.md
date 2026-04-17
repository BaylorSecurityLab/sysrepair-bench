# Unbound 1.21 — Open Recursive Resolver (DNS Amplification)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CWE-406: Insufficient Control of Network Message Volume (Network Amplification)
- CWE-284: Improper Access Control

## Description
Unbound 1.21 is configured with `access-control: 0.0.0.0/0 allow` and
`access-control: ::/0 allow`, permitting recursive DNS queries from any IPv4
or IPv6 source address. Combined with `hide-identity: no` and
`hide-version: no`, the server also discloses its software version and
identity to anyone who queries it.

**DNS Amplification attack vector:** UDP-based DNS has no three-way handshake.
An attacker can spoof the source IP of a victim and send a small query
(≈40 bytes) that elicits a large DNSSEC-signed or ANY-type response (up to
4096 bytes with EDNS0). The open resolver forwards this large response to
the spoofed victim IP. With thousands of open resolvers available, attackers
can sustain multi-Gbps floods against a victim using minimal upstream
bandwidth.

The amplification factor for DNS ANY queries can exceed 70x. Unbound's
default configuration, when bound to `0.0.0.0` without access controls,
makes this server an immediate candidate for inclusion in DDoS botnets.

**Version disclosure:** With `hide-identity` and `hide-version` disabled,
the CHAOS class queries `version.bind` and `id.server` return the exact
Unbound version string and server identity. This assists targeted
exploitation of known Unbound vulnerabilities by reducing attacker
reconnaissance effort.

```bash
# Amplification query (spoofed source = victim)
dig @<server-ip> ANY isc.org +bufsize=4096

# Version disclosure
dig @<server-ip> version.bind CHAOS TXT
dig @<server-ip> id.server CHAOS TXT
```

## Affected Service
- **Service:** Unbound 1.21
- **Port:** 53/UDP, 53/TCP
- **Vulnerable configuration:** `access-control: 0.0.0.0/0 allow`, `hide-identity: no`, `hide-version: no`

## Vulnerable Configuration
```yaml
server:
    access-control: 0.0.0.0/0 allow
    access-control: ::/0 allow
    hide-identity: no
    hide-version: no
```

## Remediation Steps
1. Restrict recursive queries to trusted sources only. Replace the open ACLs:
   ```yaml
   server:
       access-control: 0.0.0.0/0 refuse
       access-control: 127.0.0.0/8 allow
       access-control: 10.0.0.0/8 allow
       access-control: 172.16.0.0/12 allow
       access-control: 192.168.0.0/16 allow
   ```

2. Suppress version and identity disclosure to prevent reconnaissance:
   ```yaml
   server:
       hide-identity: yes
       hide-version: yes
   ```

3. Optionally set a fake version string as a honeypot indicator:
   ```yaml
   server:
       version: "DNS"
       identity: "resolver"
   ```

4. Reload Unbound and verify:
   ```bash
   unbound-control reload

   # External recursive query must be refused
   dig @<server-ip> google.com
   # Expected: status: REFUSED

   # Version disclosure must be suppressed
   dig @<server-ip> version.bind CHAOS TXT
   # Expected: REFUSED or empty

   # Local zone must still resolve
   dig @127.0.0.1 local.test A
   # Expected: 10.0.0.1
   ```
