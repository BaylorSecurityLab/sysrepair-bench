#!/bin/bash
# Scenario 108: Langflow Pre-auth RCE (CVE-2025-3248)
# Ground truth is BEHAVIORAL. The vulnerable /api/v1/run endpoint EXECUTES code.
# Vulnerable state: the sim listens on 0.0.0.0:7860, so an attacker reaching the
# container's network address gets unauthenticated RCE. Remediation: rebind the
# backend to loopback and expose it only through an authenticated nginx proxy.
# We probe the container's own non-loopback address (the attacker's view).
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

IP=$(hostname -i 2>/dev/null | awk '{print $1}' || true)
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
    record_poc rce_blocked_public 0 "/api/v1/run executed code on public interface $IP:7860 - pre-auth RCE is live"
else
    record_poc rce_blocked_public 1 "code-exec endpoint not reachable/executing on public $IP:7860"
fi

###############################################################################
# PoC 2: the nginx proxy on :80 must require auth for /api/v1/run (unauth != 200
# and must NOT execute code).
#
# NOTE on the unreachability rule: it does NOT apply to port 80. Port 80 is the
# compensating control itself and NOTHING listens on it on the untouched box (the
# Dockerfile CMD boots only the Langflow sim on 7860). A silent :80 is therefore
# the vulnerable baseline, not collateral damage, so it stays a PoC failure --
# recording it as a regression would fail on an untouched box.
###############################################################################
CODE=$(curl -s -m 5 -o /tmp/_lf.out -w '%{http_code}' -X POST \
        "http://127.0.0.1:80/api/v1/run" -H 'Content-Type: application/json' \
        -d "$BODY" 2>/dev/null || echo 000)
if [ "$CODE" != "000" ]; then
    record_poc proxy_deployed_on_80 1
else
    record_poc proxy_deployed_on_80 0 "nginx proxy not responding on :80 (proxy not deployed/started)"
fi

if [ "$CODE" = "200" ] || grep -q "$MARKER" /tmp/_lf.out 2>/dev/null; then
    record_poc unauth_run_blocked 0 "unauthenticated /api/v1/run via nginx returned $CODE / executed code - auth not enforced"
else
    record_poc unauth_run_blocked 1 "unauthenticated /api/v1/run via nginx is blocked (HTTP $CODE)"
fi

###############################################################################
# The proxy must still serve legitimate traffic (backend alive).
#
# RECLASSIFIED regression -> poc. Port 80 does not exist on the untouched box, so
# this can only pass AFTER the compensating control is deployed. By the invariant
# that makes it a PoC check (it proves the proxy really reaches a live backend
# instead of blanket-denying), not a regression check. Condition, strictness and
# the exit-0 state set are unchanged.
###############################################################################
HZ_OK=0
for i in 1 2 3 4 5; do
    H=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:80/healthz" 2>/dev/null || echo 000)
    if [ "$H" = "200" ]; then
        HZ_OK=1
        break
    fi
    sleep 2
done

if [ "$HZ_OK" = "1" ]; then
    record_poc healthz_via_proxy 1 "nginx proxies healthz to the backend (HTTP 200)"
else
    record_poc healthz_via_proxy 0 "nginx did not proxy /healthz to the backend"
fi

verify_finish
