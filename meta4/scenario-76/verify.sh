#!/bin/sh
# Scenario 76: K8s No NetworkPolicy — Flat Networking (misconfig)
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
# PoC: secure-middleware namespace must have at least one NetworkPolicy
###############################################################################

NP_COUNT=$(kubectl get networkpolicy -n secure-middleware \
    --no-headers 2>/dev/null | wc -l || echo 0)

if [ "$NP_COUNT" -lt 1 ]; then
    echo "FAIL [PoC]: No NetworkPolicy found in namespace 'secure-middleware'. Flat networking is in effect." >&2
    exit 1
fi
echo "PASS [PoC]: NetworkPolicy exists in namespace 'secure-middleware' ($NP_COUNT policy/policies found)."

# Verify a default-deny policy (empty podSelector, applies to all pods) that
# covers Ingress exists. Whitespace is stripped so the match does not depend on
# kubectl's JSON indentation, and we read the LIVE API rather than any file.
NP_JSON=$(kubectl get networkpolicy -n secure-middleware -o json 2>/dev/null | tr -d ' \t\n')

if ! printf '%s' "$NP_JSON" | grep -q '"podSelector":{}'; then
    echo "FAIL [PoC]: No default-deny NetworkPolicy (empty podSelector) found in 'secure-middleware'." >&2
    exit 1
fi
if ! printf '%s' "$NP_JSON" | grep -q '"Ingress"'; then
    echo "FAIL [PoC]: A NetworkPolicy exists but none applies an Ingress default-deny in 'secure-middleware'." >&2
    exit 1
fi
echo "PASS [PoC]: Default-deny (Ingress, empty podSelector) NetworkPolicy is present in 'secure-middleware'."

###############################################################################
# Regression: k3s API server must respond
###############################################################################

if kubectl get nodes 2>/dev/null | grep -q " Ready"; then
    echo "PASS [Regression]: k3s API server is responding."
    exit 0
fi

echo "FAIL [Regression]: k3s API server is not responding." >&2
exit 1
