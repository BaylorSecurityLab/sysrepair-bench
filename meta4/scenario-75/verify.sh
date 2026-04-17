#!/bin/sh
# Scenario 75: K8s RBAC cluster-admin ServiceAccount (misconfig)
set -u

KUBECONFIG=/etc/rancher/k3s/k3s.yaml
export KUBECONFIG

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
# PoC: superadmin ServiceAccount must NOT have cluster-admin privilege
###############################################################################

RESULT=$(kubectl auth can-i list secrets \
    --as=system:serviceaccount:default:superadmin 2>/dev/null || true)

if [ "$RESULT" = "yes" ]; then
    echo "FAIL [PoC]: superadmin ServiceAccount still has cluster-admin privilege (can list secrets cluster-wide)." >&2
    exit 1
fi
echo "PASS [PoC]: superadmin ServiceAccount cannot list secrets cluster-wide."

###############################################################################
# Regression: k3s API server must respond on port 6443
###############################################################################

if kubectl get nodes 2>/dev/null | grep -q " Ready"; then
    echo "PASS [Regression]: k3s API server is responding on port 6443."
    exit 0
fi

echo "FAIL [Regression]: k3s API server is not responding." >&2
exit 1
