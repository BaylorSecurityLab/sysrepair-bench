#!/bin/bash
# Scenario 86: HashiCorp Vault 1.13.3 — Unencrypted Storage (misconfig)
set -u

###############################################################################
# PoC 1: vault.hcl must contain a seal stanza
###############################################################################

VAULT_CFG="/vault/config/vault.hcl"

if ! grep -q 'seal' "${VAULT_CFG}" 2>/dev/null; then
    echo "FAIL [PoC]: No 'seal' stanza found in ${VAULT_CFG}." >&2
    exit 1
fi
echo "PASS [PoC]: 'seal' stanza present in vault.hcl."

###############################################################################
# PoC 2: /vault/data must not be world-readable (must be 0700 or stricter)
###############################################################################

PERMS=$(stat -c '%a' /vault/data 2>/dev/null || stat -f '%A' /vault/data 2>/dev/null)
if [ -z "${PERMS}" ]; then
    echo "FAIL [PoC]: Could not stat /vault/data." >&2
    exit 1
fi

# octal: 0700 = 700; reject anything with group or other read bits (6xx, x6x, xx6, etc.)
if [[ "${PERMS}" =~ ^7[0][0]$ ]]; then
    echo "PASS [PoC]: /vault/data permissions are ${PERMS} (0700 or stricter)."
else
    echo "FAIL [PoC]: /vault/data permissions are ${PERMS} — must be 0700 or stricter." >&2
    exit 1
fi

# PoC (behavioral): verify /vault/data is not readable by non-vault users
if id nobody >/dev/null 2>&1; then
    READABLE=$(su -s /bin/sh nobody -c 'ls /vault/data 2>&1' 2>/dev/null || echo "denied")
    if echo "$READABLE" | grep -qi 'denied\|permission'; then
        echo "PASS [PoC]: /vault/data not readable by unprivileged user."
    elif [ -n "$READABLE" ] && ! echo "$READABLE" | grep -qi 'denied'; then
        echo "FAIL [PoC]: /vault/data is readable by unprivileged user." >&2
        exit 1
    fi
fi

###############################################################################
# Regression: Vault must still be responding
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
