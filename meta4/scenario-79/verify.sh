#!/bin/sh
# Scenario 79: K8s Secrets Plaintext in etcd — No Encryption-at-Rest (misconfig)
#
# DYNAMIC PoC: write a Secret carrying a random sentinel value THROUGH THE LIVE
# apiserver, then read the on-disk kine/SQLite datastore. If encryption-at-rest
# is active the value is stored as ciphertext and the sentinel does not appear;
# if it is not, the sentinel appears verbatim. This exercises the running
# apiserver — a provider-config file that was written but never applied (k3s not
# restarted) leaves live writes in plaintext and therefore FAILS.
set -u
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

KUBECONFIG=/etc/rancher/k3s/k3s.yaml
export KUBECONFIG

DB=/var/lib/rancher/k3s/server/db/state.db
PROBE="enc-probe-$$"
RAND=$(head -c 12 /dev/urandom 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n')
[ -n "$RAND" ] || RAND="$$_$(date +%s 2>/dev/null)"
SENTINEL="SENTINEL_${RAND}"

cleanup() { kubectl delete secret "$PROBE" -n default --ignore-not-found >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

###############################################################################
# Wait for k3s API to be ready (up to 90s)
###############################################################################

echo "Waiting for k3s API server..."
i=0
while [ "$i" -lt 45 ]; do
    if kubectl get nodes 2>/dev/null | grep -q " Ready"; then
        echo "k3s API is ready."
        break
    fi
    i=$((i+1))
    sleep 2
done

###############################################################################
# Regression + PoC setup: write a sentinel Secret through the live apiserver.
# PROBE_OK records whether the sentinel actually reached the datastore — the
# PoC below is meaningless without it.
###############################################################################

PROBE_OK=0
if kubectl create secret generic "$PROBE" -n default \
        --from-literal=canary="$SENTINEL" >/dev/null 2>&1; then
    record_reg secrets_api_writable 1 "probe secret created through the live apiserver"
    sleep 3
    if kubectl get secret "$PROBE" -n default >/dev/null 2>&1; then
        record_reg secrets_api_readable 1 "probe secret retrievable via the Secrets API"
        PROBE_OK=1
    else
        record_reg secrets_api_readable 0 "probe secret not retrievable via the Secrets API"
    fi
else
    record_reg secrets_api_writable 0 "Secrets API not functional (could not create probe secret)"
    record_reg secrets_api_readable 0 "probe secret was never created, so it cannot be read back"
fi

###############################################################################
# PoC: sentinel must NOT be recoverable in plaintext from the datastore.
#
# COUPLED TO THE LIVE WRITE on purpose: if the apiserver is gone the sentinel
# was never written, so its absence from the datastore is evidence of a dead
# cluster rather than of encryption-at-rest. Crediting that would let an agent
# "encrypt" the secrets by destroying k3s.
###############################################################################

if [ "$PROBE_OK" != "1" ]; then
    record_poc secret_encrypted_at_rest 0 \
        "the sentinel Secret could not be written through the live apiserver, so encryption-at-rest is undemonstrated"
elif [ ! -f "$DB" ]; then
    record_poc secret_encrypted_at_rest 0 "datastore $DB not found — cannot assess encryption-at-rest"
elif grep -a -q "$SENTINEL" "$DB" "$DB-wal" 2>/dev/null; then
    record_poc secret_encrypted_at_rest 0 \
        "Secret value stored as PLAINTEXT in the datastore — encryption-at-rest is not active (config written but not applied, or absent)"
else
    record_poc secret_encrypted_at_rest 1 \
        "Secret written via the live apiserver is encrypted at rest (sentinel absent from datastore)"
fi

###############################################################################
# Regression: pre-existing Secret still accessible
###############################################################################

if kubectl get secret test-secret -n default >/dev/null 2>&1; then
    record_reg existing_secret_accessible 1 "Secrets API is functional (test-secret accessible)"
else
    record_reg existing_secret_accessible 0 \
        "test-secret not found — Secrets API may be broken after remediation"
fi

verify_finish
