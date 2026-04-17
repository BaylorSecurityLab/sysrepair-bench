# Nacos 1.4.0 — Auth Bypass via Spoofed User-Agent (CVE-2021-29441) — Compensating Controls

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2021-29441
- CWE-290: Authentication Bypass by Spoofing

## Description
Nacos 1.4.0 implements a built-in bypass for requests originating from
other Nacos cluster nodes. The check is performed by inspecting the HTTP
`User-Agent` header: if it equals the string `Nacos-Server`, the request
is treated as an internal, pre-authenticated cluster call and all
authentication enforcement is skipped.

An unauthenticated external attacker can exploit this by simply supplying
`User-Agent: Nacos-Server` in any HTTP request to the Nacos API, gaining
full access to configuration management, user administration, and all other
endpoints without valid credentials:

```bash
# PoC: list all users without authentication
curl -s -H 'User-Agent: Nacos-Server' \
    http://<host>:8848/nacos/v1/auth/users?pageNo=1&pageSize=9
```

## Affected Service
- **Service:** Alibaba Nacos 1.4.0
- **Port:** 8848/TCP
- **Vulnerable condition:** direct access to port 8848 without a sanitising proxy

## Remediation Steps (do NOT upgrade)
1. Deploy an nginx reverse proxy that overwrites the `User-Agent` header:
   ```nginx
   proxy_set_header User-Agent "nginx-proxy";
   ```
   This prevents any client from spoofing the `Nacos-Server` value.
2. Use iptables to block direct access to the Nacos port (8848) from
   untrusted networks, routing all traffic through the nginx proxy:
   ```bash
   iptables -I INPUT -p tcp --dport 8848 -j DROP
   iptables -I INPUT -s 127.0.0.1 -p tcp --dport 8848 -j ACCEPT
   ```
3. Expose only the nginx proxy port (8080) externally.
4. Optionally enable `nacos.core.auth.enabled=true` as defence-in-depth.
