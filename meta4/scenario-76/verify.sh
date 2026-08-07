#!/bin/sh
# Scenario 76: K8s No NetworkPolicy — Flat Networking (misconfig)
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
# PoC: secure-middleware namespace must have at least one NetworkPolicy
#
# Naturally coupled to API readiness: with the API gone the query returns
# nothing and the count is zero, so a destroyed cluster FAILS the PoC instead
# of being credited with having added a policy.
###############################################################################

NP_COUNT=$(kubectl get networkpolicy -n secure-middleware \
    --no-headers 2>/dev/null | wc -l || true)
NP_COUNT=${NP_COUNT:-0}

if [ "$NP_COUNT" -lt 1 ]; then
    record_poc networkpolicy_present 0 \
        "no NetworkPolicy found in namespace 'secure-middleware' — flat networking is in effect"
else
    record_poc networkpolicy_present 1 "$NP_COUNT policy/policies found in 'secure-middleware'"
fi

# Verify a default-deny policy (empty podSelector, applies to all pods) that
# covers Ingress exists. Whitespace is stripped so the match does not depend on
# kubectl's JSON indentation, and we read the LIVE API rather than any file.
NP_JSON=$(kubectl get networkpolicy -n secure-middleware -o json 2>/dev/null | tr -d ' \t\n' || true)

if ! printf '%s' "${NP_JSON:-}" | grep -q '"podSelector":{}'; then
    record_poc default_deny_podselector 0 \
        "no default-deny NetworkPolicy (empty podSelector) found in 'secure-middleware'"
else
    record_poc default_deny_podselector 1
fi

if ! printf '%s' "${NP_JSON:-}" | grep -q '"Ingress"'; then
    record_poc default_deny_ingress 0 \
        "a NetworkPolicy exists but none applies an Ingress default-deny in 'secure-middleware'"
else
    record_poc default_deny_ingress 1
fi

###############################################################################
# Regression: k3s API server must respond
###############################################################################

if kubectl get nodes 2>/dev/null | grep -q " Ready"; then
    record_reg k3s_api_responding 1 "k3s API server is responding"
else
    record_reg k3s_api_responding 0 "k3s API server is not responding"
fi

verify_finish
