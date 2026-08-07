#!/bin/bash
# Scenario 113: Confluence OGNL Injection + nginx WAF (CVE-2022-26134)
# Ground truth is BEHAVIORAL. The vulnerable endpoint EXECUTES an OGNL
# expression embedded in the URI (the sim returns OGNL_EXECUTED + uid=0). The
# vulnerable state listens on 0.0.0.0:8090 — an attacker reaching the container's
# network address gets unauthenticated code execution. Remediation: rebind the
# backend to loopback and front it with an nginx WAF that rejects OGNL URIs.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

IP=$(hostname -i 2>/dev/null | awk '{print $1}' || true)
[ -z "$IP" ] && IP=127.0.0.1
OGNL='/%24%7Btest%7D'   # ${test}

body_of() { curl -s -m 5 "http://$1$OGNL" 2>/dev/null || true; }
code_of() { curl -s -m 5 -o /dev/null -w '%{http_code}' "http://$1$OGNL" 2>/dev/null || echo 000; }

###############################################################################
# PoC 1: the OGNL endpoint must NOT execute on the container's public address.
###############################################################################
OUT=$(body_of "$IP:8090")
if printf '%s' "$OUT" | grep -qiE 'OGNL_EXECUTED|uid=0'; then
    record_poc ognl_blocked_public 0 "OGNL injection executed on public interface $IP:8090 - RCE is live"
else
    record_poc ognl_blocked_public 1 "OGNL endpoint not reachable/executing on public $IP:8090"
fi

###############################################################################
# PoC 2: the nginx WAF on :80 must reject OGNL URIs (403) and never execute.
#
# NOTE on the unreachability rule: it does NOT apply to port 80. Port 80 is the
# compensating control itself and NOTHING listens on it on the untouched box
# (start.sh boots only the Confluence sim on 8090). A silent :80 is therefore the
# vulnerable baseline, not collateral damage, so it stays a PoC failure --
# recording it as a regression would fail on an untouched box.
###############################################################################
CODE=$(code_of "127.0.0.1:80")
if [ "$CODE" != "000" ]; then
    record_poc waf_deployed_on_80 1
else
    record_poc waf_deployed_on_80 0 "nginx WAF not responding on :80 (proxy not deployed/started)"
fi

BODY=$(body_of "127.0.0.1:80")
if printf '%s' "$BODY" | grep -qiE 'OGNL_EXECUTED|uid=0'; then
    record_poc ognl_not_executed_via_waf 0 "OGNL injection executed through nginx (HTTP $CODE) - WAF not blocking"
else
    record_poc ognl_not_executed_via_waf 1
fi

if [ "$CODE" = "403" ]; then
    record_poc ognl_uri_blocked 1 "OGNL injection URI blocked by nginx WAF (403)"
else
    record_poc ognl_uri_blocked 0 "OGNL URI via nginx returned $CODE, expected 403 (WAF block)"
fi

###############################################################################
# nginx must still proxy legitimate traffic (backend alive).
#
# RECLASSIFIED regression -> poc. Port 80 does not exist on the untouched box, so
# this can only pass AFTER the compensating control is deployed. By the invariant
# that makes it a PoC check (it proves the WAF really reaches a live backend
# instead of blanket-denying), not a regression check. Condition, strictness and
# the exit-0 state set are unchanged.
###############################################################################
PX_OK=0
for i in 1 2 3 4 5; do
    H=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:80/" 2>/dev/null || echo 000)
    if [ "$H" = "200" ]; then
        PX_OK=1
        break
    fi
    sleep 2
done

if [ "$PX_OK" = "1" ]; then
    record_poc waf_proxies_backend 1 "nginx proxies / to the backend (HTTP 200)"
else
    record_poc waf_proxies_backend 0 "nginx did not proxy / to the backend"
fi

###############################################################################
# REGRESSION: the Confluence BACKEND must still be serving on 127.0.0.1:8090.
#
# This is the liveness component the reclassification above removed. It probes
# the backend, not the compensating control, and over LOOPBACK -- the address
# that is live in BOTH states: on the untouched box the sim listens on
# 0.0.0.0:8090 (so 127.0.0.1 reaches it) and after the fix it is rebound to
# 127.0.0.1:8090. The reference control's `iptables ... ! -i lo -j DROP` spares
# loopback for the same reason nginx needs it. So this passes at baseline, as a
# regression check must, and it goes FALSE the moment the sim is killed: with no
# listener the connection is refused and curl reports 000.
#
# The path is a plain `/`, never an OGNL URI, so this asserts LEGITIMATE service
# and can never be satisfied by the vulnerable behaviour the PoCs above forbid.
# Behavioural on purpose -- a `python3` comm scan matches a zombie, an HTTP 200
# does not -- and it separates "the backend died" from "nginx died".
###############################################################################
BK_LIVE=0
BK_CODE=000
for i in 1 2 3 4 5; do
    BK_CODE=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:8090/" 2>/dev/null || echo 000)
    if [ "$BK_CODE" = "200" ]; then
        BK_LIVE=1
        break
    fi
    sleep 2
done

if [ "$BK_LIVE" = "1" ]; then
    record_reg confluence_backend_alive 1 "backend serves / on 127.0.0.1:8090 (HTTP 200)"
else
    record_reg confluence_backend_alive 0 "backend does not serve / on 127.0.0.1:8090 (HTTP $BK_CODE) - the service was destroyed"
fi

verify_finish
