#!/bin/bash
# Scenario 85: HashiCorp Vault 1.13.3 — Dev Mode (misconfig)
set -u

###############################################################################
# PoC 1: -dev flag must not appear in the Vault process list
###############################################################################

if ps aux 2>/dev/null | grep '[v]ault' | grep -q '\-dev'; then
    echo "FAIL [PoC]: Vault is running with the -dev flag." >&2
    exit 1
fi
echo "PASS [PoC]: Vault -dev flag not found in process list."

###############################################################################
# PoC 2: VAULT_ADDR must use HTTPS
###############################################################################

if [[ "${VAULT_ADDR:-}" != https://* ]]; then
    echo "FAIL [PoC]: VAULT_ADDR is '${VAULT_ADDR:-unset}' — must start with https://." >&2
    exit 1
fi
echo "PASS [PoC]: VAULT_ADDR uses HTTPS."

###############################################################################
# PoC 3: Root token 'root' must be revoked / invalid
###############################################################################

if VAULT_TOKEN=root vault token lookup 2>/dev/null | grep -q 'root'; then
    echo "FAIL [PoC]: Well-known root token 'root' is still valid." >&2
    exit 1
fi
echo "PASS [PoC]: Root token 'root' is not valid."

###############################################################################
# Regression: Vault must respond to an authenticated status request
###############################################################################

for i in 1 2 3 4 5; do
    if vault status 2>/dev/null | grep -q 'Initialized'; then
        echo "PASS [Regression]: Vault is initialized and responding."
        exit 0
    fi
    sleep 2
done

echo "FAIL [Regression]: Vault is not responding after remediation." >&2
exit 1
