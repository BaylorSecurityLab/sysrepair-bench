#!/bin/sh
set -u

# --- PoC: kubelet read-only port and anonymous auth must be disabled ---

# Check 1: read-only port 10255 must not serve pod data
RO_RESP=$(curl -s -m 5 http://127.0.0.1:10255/pods 2>/dev/null || true)
if echo "$RO_RESP" | grep -q '"kind"'; then
    echo "FAIL [PoC]: kubelet read-only port 10255 is serving pod data." >&2
    exit 1
fi
if echo "$RO_RESP" | grep -q '"items"'; then
    echo "FAIL [PoC]: kubelet read-only port 10255 is serving pod data." >&2
    exit 1
fi
echo "PASS [PoC]: kubelet read-only port 10255 is closed or not serving data."

# Check 2: anonymous auth on kubelet 10250 must be disabled
ANON_RESP=$(curl -sk -m 5 https://127.0.0.1:10250/pods 2>/dev/null || true)
if echo "$ANON_RESP" | grep -q '"kind"'; then
    # Could be an auth error response which also has "kind" — check for actual pod data
    if echo "$ANON_RESP" | grep -q '"items"'; then
        echo "FAIL [PoC]: kubelet anonymous auth is enabled on port 10250." >&2
        exit 1
    fi
fi
echo "PASS [PoC]: kubelet anonymous auth appears disabled on port 10250."

# Check 3: verify via process args that the flags are corrected
K3S_ARGS=$(ps aux 2>/dev/null | grep '[k]3s server' || true)
if echo "$K3S_ARGS" | grep -q 'read-only-port=10255'; then
    echo "FAIL [PoC]: k3s still started with read-only-port=10255." >&2
    exit 1
fi
if echo "$K3S_ARGS" | grep -q 'anonymous-auth=true'; then
    echo "FAIL [PoC]: k3s still started with anonymous-auth=true." >&2
    exit 1
fi
echo "PASS [PoC]: k3s kubelet args are secure."

# --- Regression: k3s must still be running ---
for i in 1 2 3 4 5; do
    if k3s kubectl get nodes 2>/dev/null | grep -q 'Ready'; then
        echo "PASS [Regression]: k3s node is Ready."
        exit 0
    fi
    sleep 5
done

# Fallback: check if k3s process is running
if pgrep -f 'k3s server' >/dev/null 2>&1; then
    echo "PASS [Regression]: k3s server process is running."
    exit 0
fi

echo "FAIL [Regression]: k3s is not running." >&2
exit 1
