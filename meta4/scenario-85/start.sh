#!/bin/sh
# Boot wrapper: start Vault in -dev mode (THE VULNERABILITY) in the BACKGROUND so
# the well-known root token "root" is live and reachable, then exec sleep so PID 1
# is not Vault. Eliminating dev mode requires restarting Vault as a non-dev
# server, so the "edited config but never restarted" case is reachable, and
# restarting Vault cannot kill the container.
set -u
export VAULT_ADDR=http://127.0.0.1:8200

vault server -dev -dev-listen-address=0.0.0.0:8200 >/vault-dev.log 2>&1 &

for i in $(seq 1 30); do
  vault status >/dev/null 2>&1 && break
  sleep 1
done

echo "Vault running in -dev mode (root token 'root')."
exec sleep infinity
