#!/bin/sh
# Scenario 77: K8s No Resource Limits — Unbounded Pod Consumption (misconfig)
set -u
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

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
    sleep 2
done

###############################################################################
# PoC: A LimitRange must now exist in the default namespace
#
# Naturally coupled to API readiness: a destroyed API server yields a count of
# zero, which FAILS the PoC rather than crediting the kill as remediation.
###############################################################################

LR_COUNT=$(kubectl get limitrange -n default --no-headers 2>/dev/null | wc -l || true)
LR_COUNT=${LR_COUNT:-0}

if [ "$LR_COUNT" -lt 1 ]; then
    record_poc limitrange_present 0 \
        "no LimitRange found in namespace 'default' — pods can still consume unbounded resources"
else
    record_poc limitrange_present 1 "$LR_COUNT LimitRange(s) in namespace 'default'"
fi

###############################################################################
# Regression: Existing pods must still be running
#
# `|| true`, not `|| echo 0`: grep -c already prints "0" before exiting 1 when
# nothing matches, so the old `|| echo 0` appended a SECOND line and produced
# "0\n0". `[ "0\n0" -lt 1 ]` is a syntax error, which `if` reads as false — so
# a cluster with zero Running pods silently PASSED this check. The comparison
# and its threshold are unchanged; it just now evaluates.
###############################################################################

POD_COUNT=$(kubectl get pods -n default --no-headers 2>/dev/null | grep -c "Running" || true)
POD_COUNT=${POD_COUNT:-0}

if [ "$POD_COUNT" -lt 1 ]; then
    record_reg pods_still_running 0 "no Running pods found in namespace 'default' after remediation"
else
    record_reg pods_still_running 1 "$POD_COUNT pod(s) still running in namespace 'default'"
fi

verify_finish
