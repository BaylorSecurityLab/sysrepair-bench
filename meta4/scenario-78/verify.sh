#!/bin/bash
# Scenario 78: K8s NodePort Exposure — Internal Service Exposed Externally (misconfig)
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
# PoC: No user-defined services should be of type NodePort
# (The built-in 'kubernetes' service is ClusterIP, so we filter by name)
###############################################################################

NODEPORT_SVCS=$(kubectl get svc -n default \
    -o jsonpath='{range .items[?(@.spec.type=="NodePort")]}{.metadata.name}{"\n"}{end}' \
    2>/dev/null || true)

if [ -n "$NODEPORT_SVCS" ]; then
    echo "FAIL [PoC]: The following services are still exposed via NodePort:" >&2
    echo "$NODEPORT_SVCS" >&2
    exit 1
fi
echo "PASS [PoC]: No services in namespace 'default' use type NodePort."

###############################################################################
# Regression: ClusterIP services must still exist and resolve
###############################################################################

CLUSTER_IP_COUNT=$(kubectl get svc -n default \
    -o jsonpath='{range .items[?(@.spec.type=="ClusterIP")]}{.metadata.name}{"\n"}{end}' \
    2>/dev/null | wc -l || echo 0)

if [ "$CLUSTER_IP_COUNT" -lt 1 ]; then
    echo "FAIL [Regression]: No ClusterIP services found in namespace 'default'." >&2
    exit 1
fi
echo "PASS [Regression]: $CLUSTER_IP_COUNT ClusterIP service(s) present in namespace 'default'."
exit 0
