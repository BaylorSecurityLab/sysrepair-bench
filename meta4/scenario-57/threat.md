# CoreDNS 1.11.1 — No ACL / Rate Limit (misconfig)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CWE-284: Improper Access Control
- CWE-406: Insufficient Control of Network Message Volume (Network Amplification)

## Description
CoreDNS 1.11.1 is configured to listen on `0.0.0.0` with no `acl` plugin to
restrict which clients may query, and no `ratelimit` plugin to cap query
volume per source. Any host on the internet can send unlimited DNS queries
to this server.

This misconfiguration creates two distinct risks:

**DNS Amplification (DDoS vector):** DNS responses are typically much larger
than requests. Without rate limiting, an attacker with a spoofed source IP
can direct large volumes of DNS traffic at a victim by sending small queries
to this open server. UDP-based DNS has no handshake, making it trivial to
abuse for amplification attacks.

**Unrestricted Reconnaissance:** Without ACL controls, external hosts can
freely query all zones served by CoreDNS — including internal service
discovery zones (e.g., `.cluster.local` in Kubernetes) that were intended
for internal use only. This can expose internal hostnames, pod IPs, and
service endpoints to unauthenticated external parties.

A CoreDNS instance deployed in a Kubernetes cluster with this misconfiguration
would expose cluster-internal DNS to any external party with connectivity to
the DNS port.

## Affected Service
- **Service:** CoreDNS 1.11.1
- **Port:** 53/UDP, 53/TCP
- **Vulnerable configuration:** No `acl` or `ratelimit` plugin in Corefile

## Vulnerable Configuration
```
. {
    forward . 1.1.1.1 8.8.8.8
    cache
    log
    errors
}
```

No `acl` block to deny external sources; no `ratelimit` to cap query rates.

## Remediation Steps
1. Add an `acl` plugin block to deny external sources and allow only trusted
   subnets:
   ```
   . {
       acl {
           allow net 127.0.0.0/8
           allow net 10.0.0.0/8
           allow net 172.16.0.0/12
           allow net 192.168.0.0/16
           block
       }
       forward . 1.1.1.1 8.8.8.8
       cache
       log
       errors
   }
   ```

2. Add a `ratelimit` plugin to throttle queries per source IP:
   ```
   . {
       ratelimit 100
       acl {
           allow net 127.0.0.0/8
           block
       }
       forward . 1.1.1.1
       cache
   }
   ```

3. Reload CoreDNS with the updated Corefile:
   ```
   kill -SIGUSR1 <coredns-pid>
   ```

4. Verify that external queries are blocked while internal queries succeed:
   ```
   dig @<server-ip> local.test A   # should be blocked or REFUSED for external
   dig @127.0.0.1 local.test A     # should return 10.0.0.1
   ```
