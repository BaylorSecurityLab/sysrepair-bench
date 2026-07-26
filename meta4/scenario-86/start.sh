#!/bin/sh
# Boot wrapper: start Vault (file backend) in the BACKGROUND, then initialize and
# unseal it and write a secret so /vault/data holds real on-disk storage. PID 1
# stays as `sleep infinity`. The vulnerability is that /vault/data is world/group
# readable (0755) — remediation is a chmod, which needs no restart.
set -u
export VAULT_ADDR=http://127.0.0.1:8200

vault server -config=/vault/config/vault.hcl >/vault/vault.log 2>&1 &

# Wait until the API responds (status exit 0=unsealed, 2=sealed => up).
for i in $(seq 1 60); do
  vault status >/dev/null 2>&1
  s=$?
  if [ "$s" = "0" ] || [ "$s" = "2" ]; then break; fi
  sleep 1
done

# Initialize (single unseal key for simplicity) if not already initialized.
if ! vault status 2>/dev/null | grep -qi 'Initialized *true'; then
  vault operator init -key-shares=1 -key-threshold=1 >/vault/init.txt 2>&1
fi

UNSEAL=$(grep -i 'Unseal Key 1:' /vault/init.txt 2>/dev/null | awk '{print $NF}')
ROOT=$(grep -i 'Initial Root Token:' /vault/init.txt 2>/dev/null | awk '{print $NF}')

[ -n "$UNSEAL" ] && vault operator unseal "$UNSEAL" >/dev/null 2>&1

# Write a secret so the storage backend actually contains secret material.
if [ -n "$ROOT" ]; then
  VAULT_TOKEN="$ROOT" vault secrets enable -path=secret kv >/dev/null 2>&1 || true
  VAULT_TOKEN="$ROOT" vault kv put secret/app password=s3cr3t-value >/dev/null 2>&1 || true
fi

echo "Vault running (file backend). /vault/data holds on-disk storage."
exec sleep infinity
