#!/bin/sh
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"
#
# Scenario 38: k3s insecure kubelet — read-only port (10255) + anonymous auth (10250).
#
# Dynamic checks that hit the LIVE kubelet (no config parsing):
#   * PoC1: unauthenticated GET on the read-only port 10255 must not return pods.
#   * PoC2: an anonymous request to the kubelet HTTPS API (10250) must not be
#           authenticated as system:anonymous.
# Tool notes for this image (rancher/k3s, busybox userland):
#   * curl / ss / nc / python are ABSENT. busybox `wget` has NO https support,
#     so 10255 (plain http) is probed with wget and 10250 (https, self-signed)
#     is probed with `kubectl --server=... --insecure-skip-tls-verify` used as a
#     credential-less HTTPS client.
#   * k3s rewrites its argv to "k3s server", so the kubelet flags are NOT visible
#     in `ps`/`/proc/*/cmdline` — process-arg grepping is useless here.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "hardened the kubelet but killed k3s" is reported as
# security_pass / regression_pass rather than a bare exit 1. See lib/verifylib.sh.

KUBECONFIG=/etc/rancher/k3s/k3s.yaml
export KUBECONFIG

# --- Regression: k3s must already be up. Do NOT start it (dead = FAIL).
# The harness may run this only ~15s after boot, so poll for readiness first;
# this also disambiguates "read-only port refused because fixed" from "refused
# because k3s has not finished starting".
READY=0
i=0
while [ "$i" -lt 70 ]; do
    if kubectl get nodes 2>/dev/null | grep -q ' Ready'; then READY=1; break; fi
    i=$((i+1)); sleep 2
done
if [ "$READY" -eq 1 ]; then
    record_reg k3s_node_ready 1
else
    record_reg k3s_node_ready 0 "k3s node did not become Ready (service down)"
fi

if [ "$READY" -eq 1 ]; then
    ###########################################################################
    # PoC 1: kubelet read-only port 10255 must not serve pod data
    ###########################################################################
    RO=$(wget -q -O - -T 5 http://127.0.0.1:10255/pods 2>/dev/null || true)
    case "$RO" in
        *'"kind"'*|*'"items"'*|*PodList*)
            record_poc kubelet_readonly_port_closed 0 \
                "kubelet read-only port 10255 serves pod data unauthenticated" ;;
        *)
            record_poc kubelet_readonly_port_closed 1 \
                "kubelet read-only port 10255 is closed or serves no data" ;;
    esac

    ###########################################################################
    # PoC 2: anonymous auth on kubelet 10250 must be disabled
    # Anonymous-auth=true => the kubelet authenticates the request as
    # system:anonymous (then authz denies -> 403 mentioning system:anonymous).
    # Anonymous-auth=false => 401 Unauthorized, no system:anonymous.
    ###########################################################################
    ANON=$(kubectl --server=https://127.0.0.1:10250 --insecure-skip-tls-verify \
            --kubeconfig=/dev/null --username=x --password=x \
            get --raw /metrics --request-timeout=8s </dev/null 2>&1 || true)
    if echo "$ANON" | grep -qi 'system:anonymous'; then
        record_poc kubelet_anonymous_auth_disabled 0 \
            "kubelet 10250 authenticated an anonymous request (anonymous-auth enabled)"
    else
        record_poc kubelet_anonymous_auth_disabled 1
    fi
else
    # The node never became Ready, so a silent 10255/10250 proves nothing about
    # the kubelet configuration. Recorded as FAILED, never credited: a dead
    # kubelet serves no pod data and authenticates nobody, and that must not
    # read as a hardened kubelet. Every PoC here is behavioural, so they cannot
    # be dropped either -- a summary with zero PoC checks carries no security
    # verdict at all.
    record_poc kubelet_readonly_port_closed 0 \
        "not demonstrable: k3s node not Ready, so a silent 10255 proves nothing"
    record_poc kubelet_anonymous_auth_disabled 0 \
        "not demonstrable: k3s node not Ready, so the anonymous 10250 probe proves nothing"
fi

verify_finish
