# PowerDNS Auth 4.8 — Empty API Key (misconfig)

## Severity
**High** (CVSS 8.6)

## CVE / CWE
- CWE-1188: Initialization of a Resource with an Insecure Default Value

## Description
PowerDNS Authoritative Server 4.8 is configured with `api=yes` and
`api-key=` (empty string) in `pdns.conf`. The HTTP REST API is also
exposed on `0.0.0.0:8081` with `webserver-allow-from=0.0.0.0/0`.

When `api-key` is empty, PowerDNS accepts any request to the REST API
regardless of the `X-API-Key` header value — or its complete absence.
An unauthenticated attacker with network access to port 8081 can:

1. **Enumerate all zones** — `GET /api/v1/servers/localhost/zones`
2. **Read all DNS records** — `GET /api/v1/servers/localhost/zones/<zone>`
3. **Create, modify, or delete zones** — `POST /PATCH /DELETE` on zone endpoints
4. **Inject arbitrary DNS records** — add A, MX, TXT records for any zone
5. **Delete the entire zone** — causing denial of service for DNS resolution

This is effectively an unauthenticated remote administration interface for
the DNS server. An attacker can redirect any domain served by this server,
inject phishing records, or completely destroy DNS for the domain.

```bash
# List all zones without authentication
curl http://<server>:8081/api/v1/servers/localhost/zones
# Returns full zone list with all records
```

## Affected Service
- **Service:** PowerDNS Authoritative Server 4.8
- **Port:** 8081/TCP (API), 53/UDP+TCP (DNS)
- **Vulnerable configuration:** `api-key=` (empty) in pdns.conf

## Vulnerable Configuration
```ini
api=yes
api-key=
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
   webserver-allow-from=127.0.0.1/32,10.0.0.0/24
   ```

3. If the API is not required, disable it entirely:
   ```ini
   api=no
   webserver=no
   ```

4. Restart PowerDNS and verify the API requires authentication:
   ```bash
   # Must return 401 Unauthorized
   curl -i http://localhost:8081/api/v1/servers

   # Must return 200 with correct key
   curl -H 'X-API-Key: <your-key>' http://localhost:8081/api/v1/servers
   ```
