# HashiCorp Vault 1.13.3 — Dev Mode (misconfig)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CWE-1188: Insecure Default Initialization of Resource

## Description
HashiCorp Vault launched with the `-dev` flag starts in development mode:
the root token is hardcoded to `"root"`, TLS is disabled (plain HTTP), and all
secrets are stored in memory and lost on restart. Because the root token is
publicly known, any process or user that can reach port 8200 has unrestricted
superuser access to every secret, policy, and auth method in the cluster.

An attacker can extract all secrets with a single command:

```
VAULT_ADDR=http://target:8200 vault token lookup root
```

This is a misconfiguration, not a code vulnerability. The `-dev` flag is
explicitly documented as unsafe for production.

## Affected Service
- **Service:** HashiCorp Vault 1.13.3
- **Port:** 8200/TCP
- **Vulnerable configuration:** `vault server -dev`

## Vulnerable Configuration
- Vault started with `-dev` flag
- `VAULT_DEV_ROOT_TOKEN_ID=root` exposes a well-known superuser token
- No TLS — all traffic transmitted in plaintext
- In-memory storage — no data persistence or encryption at rest

## Remediation Steps
1. Remove the `-dev` flag and write a production `vault.hcl` config with a
   `file` or `raft` storage backend.
2. Configure TLS: supply `tls_cert_file` and `tls_key_file` in the `listener`
   stanza and set `VAULT_ADDR=https://...`.
3. Initialize Vault (`vault operator init`) to generate unseal keys and an
   initial root token, then revoke the initial root token after creating an
   operator admin account.
4. Set file permissions on the data directory to 0700 and run Vault as a
   dedicated non-root user.
