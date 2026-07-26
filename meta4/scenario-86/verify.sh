#!/bin/bash
# Scenario 86: HashiCorp Vault — world-readable file storage backend (misconfig)
#
# Vault's file backend writes the encrypted keyring and secret blobs to
# /vault/data. If that directory is world/group readable, any local user or
# co-tenant process can read Vault's on-disk files (backups, snapshots) and,
# combined with a leaked unseal key, recover secrets — bypassing the API and its
# audit log. The dynamic control is the on-disk permission state: an unprivileged
# user must not be able to read /vault/data.
#
# NOTE: an external `seal` stanza (Transit/AWSKMS/GCPCKMS/AzureKeyVault) is the
# other hardening step, but every option requires a separate KMS/Vault that does
# not exist in a single-container scenario, so it is not asserted here — the
# world-readable data directory (per threat.md) is the actual, testable vuln.
set -u
export VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200}

DATA=/vault/data

###############################################################################
# PoC 1: /vault/data must be 0700 (no group/other bits)
###############################################################################

PERMS=$(stat -c '%a' "$DATA" 2>/dev/null || stat -f '%A' "$DATA" 2>/dev/null)
if [ -z "$PERMS" ]; then
    echo "FAIL [PoC]: Could not stat $DATA." >&2
    exit 1
fi
if [ "$PERMS" != "700" ]; then
    echo "FAIL [PoC]: $DATA permissions are ${PERMS} — must be 0700 (a world/group-readable data dir exposes on-disk secrets)." >&2
    exit 1
fi
echo "PASS [PoC]: $DATA permissions are 0700."

###############################################################################
# PoC 2 (dynamic/behavioral): an unprivileged user must NOT be able to read the
# on-disk storage. This exercises the live filesystem, not just the mode bits.
###############################################################################

if id nobody >/dev/null 2>&1; then
    if su -s /bin/sh nobody -c "ls $DATA" >/dev/null 2>&1; then
        echo "FAIL [PoC]: $DATA is readable by unprivileged user 'nobody' — on-disk secrets are exposed." >&2
        exit 1
    fi
    echo "PASS [PoC]: $DATA is not readable by unprivileged user 'nobody'."
fi

###############################################################################
# Regression: Vault must still be running and responding
###############################################################################

for i in 1 2 3 4 5 6 7 8 9 10; do
    if vault status 2>/dev/null | grep -q 'Initialized'; then
        echo "PASS [Regression]: Vault is initialized and responding."
        exit 0
    fi
    sleep 2
done

echo "FAIL [Regression]: Vault is not responding after remediation." >&2
exit 1
