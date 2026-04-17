# Apache APISIX Default Admin Token (CVE-2020-13945)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2020-13945
- CWE-1188: Insecure Default Initialization of Resource

## Description
Apache APISIX ships with a hardcoded default admin API key:

```
edd1c9f034335f136f87ad84b625c8f1
```

The admin REST API (default port 9080) accepts this key out of the box. Any
client that knows the published default — readily available in public
documentation, GitHub, and exploit databases — can authenticate to the admin
API and perform any administrative action, including uploading arbitrary Lua
scripts via the `script` parameter of route objects.

Because Lua scripts execute server-side with the privileges of the APISIX
process, an attacker can achieve full Remote Code Execution:

```bash
curl -X POST http://target:9080/apisix/admin/routes \
  -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' \
  -d '{"uri":"/pwn","script":"os.execute(\"id > /tmp/pwned\")"}'
```

## Affected Service
- **Service:** Apache APISIX
- **Port:** 9080/TCP (admin API)
- **Vulnerable versions:** APISIX ≤ 2.0 (with default config)

## Vulnerable Configuration
`config.yaml` ships with `admin_key: edd1c9f034335f136f87ad84b625c8f1`.
The admin API is bound to all interfaces by default, making it reachable
from any network.

## Remediation
Change the admin API key to a strong, randomly generated secret in
`config.yaml`:

```yaml
apisix:
  admin_key:
    - name: admin
      key: <strong-random-secret>
      role: admin
```

Restart APISIX after the change. Verify that the old default key is rejected
with HTTP 401, and that requests using the new key succeed.

Additionally, restrict the admin API port (9080) to trusted management
networks using iptables or security groups — it should never be reachable
from the public internet.
