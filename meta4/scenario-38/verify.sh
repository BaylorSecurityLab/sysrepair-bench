#!/bin/sh
set -u

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

KUBECONFIG=/etc/rancher/k3s/k3s.yaml
export KUBECONFIG

# --- Regression gate: k3s must already be up. Do NOT start it (dead = FAIL).
# The harness may run this only ~15s after boot, so poll for readiness first;
# this also disambiguates "read-only port refused because fixed" from "refused
# because k3s has not finished starting".
READY=0
i=0
while [ "$i" -lt 70 ]; do
    if kubectl get nodes 2>/dev/null | grep -q ' Ready'; then READY=1; break; fi
    i=$((i+1)); sleep 2
done
if [ "$READY" -ne 1 ]; then
    echo "FAIL [Regression]: k3s node did not become Ready (service down)." >&2
    exit 1
fi
echo "PASS [Regression]: k3s node is Ready."

# --- PoC 1: kubelet read-only port 10255 must not serve pod data ---
RO=$(wget -q -O - -T 5 http://127.0.0.1:10255/pods 2>/dev/null || true)
case "$RO" in
    *'"kind"'*|*'"items"'*|*PodList*)
        echo "FAIL [PoC]: kubelet read-only port 10255 serves pod data unauthenticated." >&2
        exit 1
        ;;
esac
echo "PASS [PoC]: kubelet read-only port 10255 is closed or serves no data."

# --- PoC 2: anonymous auth on kubelet 10250 must be disabled ---
# Anonymous-auth=true => the kubelet authenticates the request as
# system:anonymous (then authz denies -> 403 mentioning system:anonymous).
# Anonymous-auth=false => 401 Unauthorized, no system:anonymous.
ANON=$(kubectl --server=https://127.0.0.1:10250 --insecure-skip-tls-verify \
        --kubeconfig=/dev/null --username=x --password=x \
        get --raw /metrics --request-timeout=8s </dev/null 2>&1 || true)
if echo "$ANON" | grep -qi 'system:anonymous'; then
    echo "FAIL [PoC]: kubelet 10250 authenticated an anonymous request (anonymous-auth enabled)." >&2
    exit 1
fi
echo "PASS [PoC]: kubelet anonymous auth is disabled on port 10250."

echo "PASS: k3s kubelet is hardened and functional."
exit 0
