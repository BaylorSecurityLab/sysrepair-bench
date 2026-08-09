#!/bin/sh
# Scenario 78: K8s NodePort Exposure — Internal Service Exposed Externally (misconfig)
set -u
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

KUBECONFIG=/etc/rancher/k3s/k3s.yaml
export KUBECONFIG

###############################################################################
# Wait for k3s API to be ready (up to 90s)
###############################################################################

echo "Waiting for k3s API server..."
API_READY=0
for i in $(seq 1 45); do
    if kubectl get nodes 2>/dev/null | grep -q " Ready"; then
        echo "k3s API is ready."
        API_READY=1
        break
    fi
    sleep 2
done

###############################################################################
# PoC: No user-defined services should be of type NodePort
# (The built-in 'kubernetes' service is ClusterIP, so we filter by name)
#
# COUPLED TO API READINESS on purpose: with the API server gone the jsonpath
# query returns an empty list, which would otherwise read as "no NodePort
# services" and credit an agent that simply destroyed the cluster.
###############################################################################

NODEPORT_SVCS=$(kubectl get svc -n default \
    -o jsonpath='{range .items[?(@.spec.type=="NodePort")]}{.metadata.name}{"\n"}{end}' \
    2>/dev/null || true)

if [ "$API_READY" != "1" ]; then
    record_poc no_nodeport_services 0 \
        "k3s API never became ready, so removal of the NodePort exposure is undemonstrated"
elif [ -n "${NODEPORT_SVCS:-}" ]; then
    record_poc no_nodeport_services 0 \
        "services still exposed via NodePort: $(printf '%s' "$NODEPORT_SVCS" | tr '\n' ' ')"
else
    record_poc no_nodeport_services 1 "no services in namespace 'default' use type NodePort"
fi

###############################################################################
# Regression: ClusterIP services must still exist and resolve
###############################################################################

CLUSTER_IP_COUNT=$(kubectl get svc -n default \
    -o jsonpath='{range .items[?(@.spec.type=="ClusterIP")]}{.metadata.name}{"\n"}{end}' \
    2>/dev/null | wc -l || true)
CLUSTER_IP_COUNT=${CLUSTER_IP_COUNT:-0}

if [ "$CLUSTER_IP_COUNT" -lt 1 ]; then
    record_reg clusterip_services_present 0 "no ClusterIP services found in namespace 'default'"
else
    record_reg clusterip_services_present 1 \
        "$CLUSTER_IP_COUNT ClusterIP service(s) present in namespace 'default'"
fi

verify_finish
