#!/bin/sh
# Scenario 75: K8s RBAC cluster-admin ServiceAccount (misconfig)
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
# PoC: superadmin ServiceAccount must NOT have cluster-admin privilege
#
# COUPLED TO API READINESS on purpose: with the API server gone `kubectl auth
# can-i` prints nothing, which is not "yes" and would silently be credited as
# the binding having been removed. An unreachable cluster proves nothing.
###############################################################################

RESULT=$(kubectl auth can-i list secrets \
    --as=system:serviceaccount:default:superadmin 2>/dev/null || true)

if [ "$API_READY" != "1" ]; then
    record_poc superadmin_not_cluster_admin 0 \
        "k3s API never became ready, so removal of the cluster-admin binding is undemonstrated"
elif [ "${RESULT:-}" = "yes" ]; then
    record_poc superadmin_not_cluster_admin 0 \
        "superadmin ServiceAccount still has cluster-admin privilege (can list secrets cluster-wide)"
else
    record_poc superadmin_not_cluster_admin 1 "superadmin ServiceAccount cannot list secrets cluster-wide"
fi

###############################################################################
# Regression: k3s API server must respond on port 6443
###############################################################################

if kubectl get nodes 2>/dev/null | grep -q " Ready"; then
    record_reg k3s_api_responding 1 "k3s API server is responding on port 6443"
else
    record_reg k3s_api_responding 0 "k3s API server is not responding"
fi

verify_finish
