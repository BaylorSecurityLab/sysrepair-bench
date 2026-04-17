# HashiCorp Vault 1.13.3 — Unencrypted Storage (misconfig)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CWE-312: Cleartext Storage of Sensitive Information

## Description
Vault's file storage backend writes the encrypted keyring and all secret blobs
to `/vault/data`. When no `seal` stanza is configured, Vault uses its built-in
Shamir unseal mechanism, which is acceptable — but if the data directory
permissions are too permissive (e.g., 0755), any local user or container
process can read the raw files. Combined with a leaked unseal key or a
misconfigured auto-unseal that exposes the master key, all secrets stored on
disk become recoverable without going through the Vault API.

Additionally, without an external seal (Transit, AWSKMS, GCP CKMS, etc.),
operators must manually unseal Vault after every restart by providing unseal
key shards — there is no auditability of when the seal was broken.

## Affected Service
- **Service:** HashiCorp Vault 1.13.3
- **Port:** 8200/TCP
- **Vulnerable configuration:** File backend, no `seal` stanza, `/vault/data` at 0755

## Vulnerable Configuration
- No `seal` stanza in `vault.hcl` — no auto-unseal with external KMS
- `/vault/data` directory permissions set to 0755 (world-readable)
- Secrets at rest lack an additional envelope encryption layer via a KMS

## Remediation Steps
1. Add a `seal` stanza to `vault.hcl` to enable Transit auto-unseal or an
   equivalent KMS seal (AWSKMS, GCP CKMS, AzureKeyVault).
2. Restrict `/vault/data` to mode 0700 owned by the Vault service account:
   ```
   chmod 0700 /vault/data
   chown vault:vault /vault/data
   ```
3. Rotate the unseal keys after applying the new seal configuration using
   `vault operator rekey`.
4. Enable audit logging so that every secret access is recorded.
