# PowerDNS Auth — Weak / Default API Key (misconfig)

## Severity
**High** (CVSS 8.6)

## CVE / CWE
- CWE-521: Weak Password Requirements
- CWE-798: Use of Hard-coded / Default Credentials

## Description
The PowerDNS Authoritative Server (Debian bookworm ships 4.7.x) is configured
with `api=yes` and a **weak, well-known api-key** (`powerdns`) in `pdns.conf`.
The HTTP REST API is exposed on `0.0.0.0:8081` with
`webserver-allow-from=0.0.0.0/0`.

Because the API key is a trivially guessable default, an attacker with network
access to port 8081 can present `X-API-Key: powerdns` and:

1. **Enumerate all zones** — `GET /api/v1/servers/localhost/zones`
2. **Read all DNS records** — `GET /api/v1/servers/localhost/zones/<zone>`
3. **Create, modify, or delete zones** — `POST /PATCH /DELETE` on zone endpoints
4. **Inject arbitrary DNS records** — add A, MX, TXT records for any zone
5. **Delete the entire zone** — causing denial of service for DNS resolution

This is effectively a remote administration interface protected only by a
guessable password.

```bash
# List all zones with the guessable default key
curl -H 'X-API-Key: powerdns' http://<server>:8081/api/v1/servers/localhost/zones
```

> **Important — the "empty api-key" myth.** On this PowerDNS version an *empty*
> `api-key=` does **not** open the API; the server rejects every request with
> `401 Unauthorized` (the API is effectively locked). The genuine,
> behaviourally reproducible misconfiguration is therefore a *weak* key, not an
> empty one. The remediation must **rotate** the key to a strong random value —
> merely blanking it would break the API rather than secure it.

## Affected Service
- **Service:** PowerDNS Authoritative Server 4.7.x (bookworm)
- **Port:** 8081/TCP (API), 53/UDP+TCP (DNS)
- **Vulnerable configuration:** `api-key=powerdns` (weak default) in pdns.conf

## Vulnerable Configuration
```ini
api=yes
api-key=powerdns
webserver=yes
webserver-address=0.0.0.0
webserver-port=8081
webserver-allow-from=0.0.0.0/0,::/0
```

## Remediation Steps
1. Set a strong, randomly generated API key (minimum 32 characters):
   ```ini
   api-key=<random-64-char-hex-string>
   ```
   Generate one with: `openssl rand -hex 32`

2. Restrict the webserver to localhost or management networks only:
   ```ini
   webserver-allow-from=127.0.0.1/32,::1/128
   ```

3. If the API is not required, disable it entirely:
   ```ini
   api=no
   webserver=no
   ```

4. Restart PowerDNS and verify the guessable key no longer works and the new
   key does:
   ```bash
   # Must NOT return 200 (weak key rotated out)
   curl -i -H 'X-API-Key: powerdns' http://localhost:8081/api/v1/servers
   # Must return 200 with the new key
   curl -H 'X-API-Key: <your-new-key>' http://localhost:8081/api/v1/servers
   ```
