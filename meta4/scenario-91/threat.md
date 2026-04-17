# Grafana 8.3.0 — Path Traversal (CVE-2021-43798)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CVE-2021-43798
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

## Description
Grafana 8.3.0 and earlier versions contain a path traversal vulnerability in the
plugin static file serving endpoint. The URL pattern
`/public/plugins/<plugin-id>/../../../../<path>` bypasses the intended directory
restriction and allows an unauthenticated remote attacker to read arbitrary files
from the host filesystem. Any file readable by the `grafana` process — including
`/etc/passwd`, private keys, and configuration files containing credentials — can
be exfiltrated with a single HTTP GET request requiring no authentication.

Example exploit request:
```
GET /public/plugins/alertlist/../../../../etc/passwd HTTP/1.1
```

## Affected Service
- **Service:** Grafana 8.3.0
- **Port:** 3000/TCP
- **Vulnerable endpoint:** `/public/plugins/<plugin-id>/` (static file handler)

## Vulnerable Configuration
- Grafana 8.3.0 — path traversal sequences not sanitised in plugin static handler
- No authentication required for the `/public/` endpoint tree

## Remediation Steps (Compensating Controls — do NOT upgrade)
1. Place an nginx reverse proxy in front of Grafana on port 3000. Configure a
   `location` block for `/public/plugins/` that rejects any request containing
   `..` (encoded or literal):
   ```nginx
   location ~ /public/plugins/.*\.\. {
       return 400;
   }
   ```
2. Disable all unused plugins in `/etc/grafana/grafana.ini` by listing only
   required plugins under `[plugins]` and setting
   `allow_loading_unsigned_plugins =` to an empty value.
3. Verify the traversal path now returns HTTP 400 or 404 rather than file content:
   ```
   curl -v http://localhost:3000/public/plugins/alertlist/../../../../etc/passwd
   ```
4. Confirm Grafana UI still loads normally at `http://localhost:3000`.
