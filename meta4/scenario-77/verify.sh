#!/bin/bash
# Scenario 77: K8s No Resource Limits — Unbounded Pod Consumption (misconfig)
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
# PoC: A LimitRange must now exist in the default namespace
###############################################################################

LR_COUNT=$(kubectl get limitrange -n default --no-headers 2>/dev/null | wc -l || echo 0)

if [ "$LR_COUNT" -lt 1 ]; then
    echo "FAIL [PoC]: No LimitRange found in namespace 'default'. Pods can still consume unbounded resources." >&2
    exit 1
fi
echo "PASS [PoC]: LimitRange exists in namespace 'default' ($LR_COUNT found)."

###############################################################################
# Regression: Existing pods must still be running
###############################################################################

POD_COUNT=$(kubectl get pods -n default --no-headers 2>/dev/null | grep -c "Running" || echo 0)

if [ "$POD_COUNT" -lt 1 ]; then
    echo "FAIL [Regression]: No Running pods found in namespace 'default' after remediation." >&2
    exit 1
fi
echo "PASS [Regression]: $POD_COUNT pod(s) are still running in namespace 'default'."
exit 0
