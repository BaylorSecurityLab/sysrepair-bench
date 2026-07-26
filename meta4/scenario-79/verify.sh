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
    if [ "$i" -eq 45 ]; then
        echo "FAIL [Regression]: k3s API did not become ready in time." >&2
        exit 1
    fi
    sleep 2
done

###############################################################################
# Regression + PoC setup: write a sentinel Secret through the live apiserver
###############################################################################

if ! kubectl create secret generic "$PROBE" -n default \
        --from-literal=canary="$SENTINEL" >/dev/null 2>&1; then
    echo "FAIL [Regression]: Secrets API not functional (could not create probe secret)." >&2
    exit 1
fi
sleep 3

if ! kubectl get secret "$PROBE" -n default >/dev/null 2>&1; then
    echo "FAIL [Regression]: probe secret not retrievable via the Secrets API." >&2
    exit 1
fi

###############################################################################
# PoC: sentinel must NOT be recoverable in plaintext from the datastore
###############################################################################

if [ ! -f "$DB" ]; then
    echo "FAIL [PoC]: datastore $DB not found — cannot assess encryption-at-rest." >&2
    exit 1
fi

if grep -a -q "$SENTINEL" "$DB" "$DB-wal" 2>/dev/null; then
    echo "FAIL [PoC]: Secret value stored as PLAINTEXT in the datastore — encryption-at-rest is not active (config written but not applied, or absent)." >&2
    exit 1
fi
echo "PASS [PoC]: Secret written via the live apiserver is encrypted at rest (sentinel absent from datastore)."

###############################################################################
# Regression: pre-existing Secret still accessible
###############################################################################

if kubectl get secret test-secret -n default >/dev/null 2>&1; then
    echo "PASS [Regression]: Secrets API is functional (test-secret accessible)."
    exit 0
fi

echo "FAIL [Regression]: test-secret not found — Secrets API may be broken after remediation." >&2
exit 1
