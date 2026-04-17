# BIND 9.18 — Open Recursive Resolver (misconfig)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CWE-406: Insufficient Control of Network Message Volume (Network Amplification)

## Description
BIND 9.18 is configured with `recursion yes; allow-recursion { any; };` in
`named.conf.options`. This turns the server into an open recursive resolver:
any host on the internet can send a DNS query and receive a recursive answer,
using this server as a free amplifier.

DNS amplification is a well-documented DDoS technique. A small UDP request
(≈40 bytes) can elicit a large response (up to 4096 bytes with EDNS0),
yielding an amplification factor of 100x or more. Attackers spoof the source
IP of a victim and flood thousands of open resolvers simultaneously; the
victim receives traffic volumes far exceeding their link capacity.

An unauthenticated attacker with any network path to port 53/UDP can:
1. Query arbitrary external domains and receive full recursive answers.
2. Use the server as an amplifier against third-party victims.
3. Extract internal zone data through recursive queries if internal zones
   are served from the same instance.

```
dig @<server-ip> ANY isc.org +bufsize=4096
```

returns a large DNSSEC-signed answer set — a single query from a spoofed
source becomes a multi-kilobyte flood against the victim.

## Affected Service
- **Service:** BIND 9.18
- **Port:** 53/UDP, 53/TCP
- **Vulnerable configuration:** `allow-recursion { any; };` in named.conf.options

## Vulnerable Configuration
```
options {
    recursion yes;
    allow-recursion { any; };
};
```

## Remediation Steps
1. Restrict recursive queries to trusted sources only — replace the vulnerable
   `allow-recursion` ACL:
   ```
   options {
       recursion yes;
       allow-recursion { localhost; localnets; };
   };
   ```
2. If this server is an authoritative-only server (not a resolver), disable
   recursion entirely:
   ```
   options {
       recursion no;
   };
   ```
3. Reload BIND after the change:
   ```
   rndc reload
   ```
4. Verify with an external query — it must return REFUSED:
   ```
   dig @<server-ip> google.com
   # Expected: status: REFUSED
   ```
