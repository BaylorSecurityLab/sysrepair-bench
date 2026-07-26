#!/bin/bash
# Scenario 108: Langflow Pre-auth RCE (CVE-2025-3248)
# Ground truth is BEHAVIORAL. The vulnerable /api/v1/run endpoint EXECUTES code.
# Vulnerable state: the sim listens on 0.0.0.0:7860, so an attacker reaching the
# container's network address gets unauthenticated RCE. Remediation: rebind the
# backend to loopback and expose it only through an authenticated nginx proxy.
# We probe the container's own non-loopback address (the attacker's view).
set -u
IP=$(hostname -i 2>/dev/null | awk '{print $1}')
[ -z "$IP" ] && IP=127.0.0.1
MARKER="PWNED$$MARK"
BODY="{\"code\":\"print('${MARKER}')\"}"

rce_out() { # $1=host:port -> response body of the run endpoint
    curl -s -m 5 -X POST "http://$1/api/v1/run" \
        -H 'Content-Type: application/json' -d "$BODY" 2>/dev/null || true
}

###############################################################################
# PoC 1: the code-exec endpoint must NOT be reachable (and executing) on the
# container's public network address.
###############################################################################
OUT=$(rce_out "$IP:7860")
if printf '%s' "$OUT" | grep -q "$MARKER"; then
    echo "FAIL [PoC]: /api/v1/run executed code on public interface $IP:7860 — pre-auth RCE is live." >&2
    exit 1
fi
echo "PASS [PoC]: code-exec endpoint not reachable/executing on public $IP:7860."

###############################################################################
# PoC 2: the nginx proxy on :80 must require auth for /api/v1/run (unauth != 200
# and must NOT execute code).
###############################################################################
CODE=$(curl -s -m 5 -o /tmp/_lf.out -w '%{http_code}' -X POST \
        "http://127.0.0.1:80/api/v1/run" -H 'Content-Type: application/json' \
        -d "$BODY" 2>/dev/null || echo 000)
if [ "$CODE" = "000" ]; then
    echo "FAIL [PoC]: nginx proxy not responding on :80 (proxy not deployed/started)." >&2
    exit 1
fi
if [ "$CODE" = "200" ] || grep -q "$MARKER" /tmp/_lf.out 2>/dev/null; then
    echo "FAIL [PoC]: unauthenticated /api/v1/run via nginx returned $CODE / executed code — auth not enforced." >&2
    exit 1
fi
echo "PASS [PoC]: unauthenticated /api/v1/run via nginx is blocked (HTTP $CODE)."

###############################################################################
# Regression: the proxy must still serve legitimate traffic (backend alive).
###############################################################################
for i in 1 2 3 4 5; do
    H=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:80/healthz" 2>/dev/null || echo 000)
    if [ "$H" = "200" ]; then
        echo "PASS [Regression]: nginx proxies healthz to the backend (HTTP 200)."
        exit 0
    fi
    sleep 2
done
echo "FAIL [Regression]: nginx did not proxy /healthz to the backend." >&2
exit 1
