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
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"
export VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200}

DATA=/vault/data

###############################################################################
# PoC 1: /vault/data must be 0700 (no group/other bits)
###############################################################################

PERMS=$(stat -c '%a' "$DATA" 2>/dev/null || stat -f '%A' "$DATA" 2>/dev/null || true)
if [ -z "${PERMS:-}" ]; then
    record_poc data_dir_mode_0700 0 "could not stat $DATA"
elif [ "$PERMS" != "700" ]; then
    record_poc data_dir_mode_0700 0 \
        "$DATA permissions are ${PERMS} — must be 0700 (a world/group-readable data dir exposes on-disk secrets)"
else
    record_poc data_dir_mode_0700 1 "$DATA permissions are 0700"
fi

###############################################################################
# PoC 2 (dynamic/behavioral): an unprivileged user must NOT be able to read the
# on-disk storage. This exercises the live filesystem, not just the mode bits.
###############################################################################

if id nobody >/dev/null 2>&1; then
    if su -s /bin/sh nobody -c "ls $DATA" >/dev/null 2>&1; then
        record_poc data_dir_unreadable_by_nobody 0 \
            "$DATA is readable by unprivileged user 'nobody' — on-disk secrets are exposed"
    else
        record_poc data_dir_unreadable_by_nobody 1 "$DATA is not readable by unprivileged user 'nobody'"
    fi
fi

###############################################################################
# Regression: Vault must still be running and responding
###############################################################################

VAULT_UP=0
for i in 1 2 3 4 5 6 7 8 9 10; do
    if vault status 2>/dev/null | grep -q 'Initialized'; then
        VAULT_UP=1
        break
    fi
    sleep 2
done

if [ "$VAULT_UP" = "1" ]; then
    record_reg vault_responding 1 "Vault is initialized and responding"
else
    record_reg vault_responding 0 "Vault is not responding after remediation"
fi

verify_finish
