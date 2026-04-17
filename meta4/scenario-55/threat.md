# BIND 9.18 — AXFR Zone Transfer Open (misconfig)

## Severity
**Medium** (CVSS 5.3)

## CVE / CWE
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

## Description
BIND 9.18 is configured with `allow-transfer { any; };` both globally in
`named.conf.options` and per-zone in `named.conf.local`. This permits any
host to request a full DNS zone transfer (AXFR) over TCP port 53.

A zone transfer returns every DNS record in a zone in a single response:
A records, MX records, CNAME records, TXT records, and internal hostnames.
For an attacker performing reconnaissance, this is equivalent to receiving a
complete map of the target's internal network topology — host names, internal
IP addresses, mail servers, load balancers, and application servers — without
any authentication.

```
dig AXFR local.test @<server-ip>
```

returns the complete zone, potentially exposing:
- Internal hostnames (db.local.test, app.local.test, admin.local.test)
- Internal IP ranges
- Mail server configuration
- Service enumeration targets for follow-on attacks

Zone transfers should only be permitted to authorised secondary name servers,
and ideally protected by TSIG (Transaction Signature) keys.

## Affected Service
- **Service:** BIND 9.18
- **Port:** 53/TCP
- **Vulnerable configuration:** `allow-transfer { any; };` in named.conf.options and zone blocks

## Vulnerable Configuration
```
options {
    allow-transfer { any; };
};

zone "local.test" {
    type master;
    allow-transfer { any; };
};
```

## Remediation Steps
1. Deny zone transfers globally unless explicitly required:
   ```
   options {
       allow-transfer { none; };
   };
   ```
2. If secondary nameservers exist, restrict transfers to their specific IPs:
   ```
   options {
       allow-transfer { 192.168.1.2; 192.168.1.3; };
   };
   ```
3. For stronger security, require TSIG key authentication for all transfers:
   ```
   zone "local.test" {
       type master;
       allow-transfer { key secondary-key; };
   };
   ```
4. Reload BIND and verify AXFR is refused:
   ```
   rndc reload
   dig AXFR local.test @<server-ip>
   # Expected: Transfer failed or REFUSED
   ```
