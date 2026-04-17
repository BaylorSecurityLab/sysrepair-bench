# HashiCorp Consul 1.15.4 — No ACL (misconfig)

## Severity
**Critical** (CVSS 9.1)

## CVE / CWE
- CWE-284: Improper Access Control

## Description
HashiCorp Consul ships with its ACL system disabled by default. When
`acl { enabled = false }` (or the stanza is absent entirely), any client that
can reach the HTTP API on port 8500 can perform every operation without a
token: read and write arbitrary KV pairs, register and deregister services,
query the full service catalog, modify intentions, and read Connect
certificates.

An attacker with network access can exfiltrate all application configuration
stored in the KV store with a single request:

```
curl http://consul-host:8500/v1/kv/?recurse
```

They can also inject malicious service records or redirect traffic by
manipulating service registrations.

## Affected Service
- **Service:** HashiCorp Consul 1.15.4
- **Port:** 8500/TCP (HTTP API), 8600/UDP+TCP (DNS)
- **Vulnerable configuration:** `acl { enabled = false }`

## Vulnerable Configuration
- `acl.enabled = false` — no token enforcement on any API endpoint
- `acl.default_policy` not set to `"deny"` — unauthenticated requests allowed

## Remediation Steps
1. Set `acl { enabled = true, default_policy = "deny" }` in `consul.hcl`.
2. Bootstrap the ACL system to obtain the initial management token:
   ```
   consul acl bootstrap
   ```
3. Create scoped tokens for each service and operator role with the minimum
   required policies.
4. Set `CONSUL_HTTP_TOKEN` (or pass `-token`) in all Consul CLI calls and
   client agent configurations.
5. Verify that an anonymous request returns HTTP 403:
   ```
   curl -s -o /dev/null -w "%{http_code}" http://localhost:8500/v1/kv/test
   # Expected: 403
   ```
