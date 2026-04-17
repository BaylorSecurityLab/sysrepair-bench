# Elasticsearch 7.10.1 — X-Pack Security Disabled (misconfig)

## Severity
**High** (CVSS 9.1)

## CVE / CWE
- CWE-284: Improper Access Control

## Description
Elasticsearch 7.10.1 ships with X-Pack security disabled by default
(`xpack.security.enabled: false`). With security off, the REST API exposed on
port 9200 requires no authentication and enforces no authorization. Any client
with network access to the host can:

- Read all stored data across all indices via `GET /_search`
- Write, update, and delete documents
- Create or delete indices and index templates
- Access cluster settings and node information
- Modify security-relevant configuration via the API

There is no network-level protection either: the server binds to all
interfaces by default. A one-liner attack:

```
curl http://<host>:9200/_cat/indices?v
```

returns a full listing of all indices and document counts without any
authentication.

## Affected Service
- **Service:** Elasticsearch 7.10.1
- **Port:** 9200/TCP (REST API), 9300/TCP (transport)
- **Vulnerable configuration:** `xpack.security.enabled=false` (environment variable or `elasticsearch.yml`)

## Vulnerable Configuration
- `xpack.security.enabled: false` in `elasticsearch.yml` or via environment
- No `network.host` restriction (binds to all interfaces)
- No TLS configured on the HTTP or transport layers

## Remediation Steps
1. Enable X-Pack security in `elasticsearch.yml` (or via the equivalent
   environment variable):
   ```yaml
   xpack.security.enabled: true
   xpack.security.transport.ssl.enabled: true
   ```
2. Generate TLS certificates and configure the transport and HTTP layers:
   ```
   bin/elasticsearch-certutil cert --silent --pem -out /tmp/certs.zip
   ```
3. Bootstrap the built-in user passwords:
   ```
   bin/elasticsearch-setup-passwords auto
   ```
   Save the generated passwords securely — the `elastic` superuser password
   is needed for subsequent API calls.
4. Restrict the bind address to the loopback or a private interface in
   `elasticsearch.yml`:
   ```yaml
   network.host: 127.0.0.1
   ```
5. Verify that unauthenticated requests return HTTP 401 and that authenticated
   requests succeed:
   ```
   curl -u elastic:<password> http://localhost:9200/_cluster/health
   # expected: {"status":"green"} or "yellow"
   ```
