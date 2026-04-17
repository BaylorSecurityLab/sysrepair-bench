#!/bin/sh
# Scenario 79: K8s Secrets Plaintext in etcd — No Encryption-at-Rest (misconfig)
set -u

KUBECONFIG=/etc/rancher/k3s/k3s.yaml
export KUBECONFIG

ENCRYPTION_CONFIG=/etc/rancher/k3s/encryption-config.yaml

###############################################################################
# Wait for k3s API to be ready (up to 90s)
###############################################################################

echo "Waiting for k3s API server..."
for i in $(seq 1 45); do
    if kubectl get nodes 2>/dev/null | grep -q " Ready"; then
        echo "k3s API is ready."
        break
    fi
    if [ "$i" -eq 45 ]; then
        echo "FAIL [Regression]: k3s API did not become ready in time." >&2
        exit 1
    fi
    sleep 2
done

###############################################################################
# PoC: Encryption configuration file must exist
###############################################################################

if [ ! -f "$ENCRYPTION_CONFIG" ]; then
    echo "FAIL [PoC]: Encryption config file not found at $ENCRYPTION_CONFIG. Secrets are stored as plaintext in etcd." >&2
    exit 1
fi
echo "PASS [PoC]: Encryption config file exists at $ENCRYPTION_CONFIG."

# PoC: The config must reference aescbc or secretbox
if ! grep -qE 'aescbc|secretbox' "$ENCRYPTION_CONFIG" 2>/dev/null; then
    echo "FAIL [PoC]: Encryption config does not reference 'aescbc' or 'secretbox' provider. Plaintext storage may still be in effect." >&2
    exit 1
fi
echo "PASS [PoC]: Encryption config references a strong encryption provider (aescbc or secretbox)."

###############################################################################
# Regression: Secrets API must still function
###############################################################################

if kubectl get secret test-secret -n default 2>/dev/null | grep -q "test-secret"; then
    echo "PASS [Regression]: Secrets API is functional (test-secret is accessible)."
    exit 0
fi

echo "FAIL [Regression]: test-secret not found — Secrets API may be broken after remediation." >&2
exit 1
