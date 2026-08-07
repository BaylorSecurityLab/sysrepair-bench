#!/bin/bash
# Scenario 105: Next.js Middleware Auth Bypass (CVE-2025-29927)
# Ground truth is BEHAVIORAL. Setting the internal header x-middleware-subrequest
# makes Next.js skip middleware, so /protected (normally 401) returns 200 with
# the secret. Vulnerable state: the app listens on 0.0.0.0:3000, so an attacker
# reaching the container's address gets the bypass. Remediation: rebind the app
# to loopback and front it with an nginx proxy that STRIPS the header.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

IP=$(hostname -i 2>/dev/null | awk '{print $1}' || true)
[ -z "$IP" ] && IP=127.0.0.1
HDR='x-middleware-subrequest: middleware'

###############################################################################
# PoC 1: the bypass must NOT work on the container's public address:3000
###############################################################################
BODY=$(curl -s -m 5 -H "$HDR" "http://$IP:3000/protected" 2>/dev/null || true)
CODE=$(curl -s -m 5 -o /dev/null -w '%{http_code}' -H "$HDR" "http://$IP:3000/protected" 2>/dev/null || echo 000)
if [ "$CODE" = "200" ] || printf '%s' "$BODY" | grep -qi 'Secret data'; then
    record_poc bypass_blocked_public 0 "middleware bypass works on public $IP:3000 (HTTP $CODE) - /protected exposed"
else
    record_poc bypass_blocked_public 1 "middleware bypass not reachable on public $IP:3000 ($CODE)"
fi

###############################################################################
# PoC 2: through the nginx proxy on :80 the bypass header must be stripped, so
# /protected still returns 401 (not 200 / not the secret).
#
# NOTE on the unreachability rule: it does NOT apply to port 80. Port 80 is the
# compensating control itself and NOTHING listens on it on the untouched box (the
# Dockerfile CMD boots only Next.js on 3000). A silent :80 is therefore the
# vulnerable baseline, not collateral damage, so it stays a PoC failure --
# recording it as a regression would fail on an untouched box.
###############################################################################
CODE=$(curl -s -m 5 -o /dev/null -w '%{http_code}' -H "$HDR" "http://127.0.0.1:80/protected" 2>/dev/null || echo 000)
BODY=$(curl -s -m 5 -H "$HDR" "http://127.0.0.1:80/protected" 2>/dev/null || true)
if [ "$CODE" != "000" ]; then
    record_poc proxy_deployed_on_80 1
else
    record_poc proxy_deployed_on_80 0 "nginx proxy not responding on :80 (proxy not deployed/started)"
fi

if [ "$CODE" = "200" ] || printf '%s' "$BODY" | grep -qi 'Secret data'; then
    record_poc bypass_header_stripped 0 "bypass header not stripped by nginx - /protected returned $CODE"
else
    record_poc bypass_header_stripped 1 "nginx strips x-middleware-subrequest - /protected returns $CODE (not 200)"
fi

###############################################################################
# The public landing page must still be served via nginx on :80.
#
# RECLASSIFIED regression -> poc. Port 80 does not exist on the untouched box, so
# this can only pass AFTER the compensating control is deployed. By the invariant
# that makes it a PoC check (it proves the proxy really serves the app instead of
# blanket-denying), not a regression check. Condition, strictness and the exit-0
# state set are unchanged.
###############################################################################
LP_OK=0
for i in 1 2 3 4 5; do
    H=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:80/" 2>/dev/null || echo 000)
    if [ "$H" = "200" ]; then
        LP_OK=1
        break
    fi
    sleep 2
done

if [ "$LP_OK" = "1" ]; then
    record_poc landing_page_via_proxy 1 "/ returns 200 via nginx on port 80"
else
    record_poc landing_page_via_proxy 0 "/ not served via nginx on :80"
fi

###############################################################################
# REGRESSION: the Next.js BACKEND must still be serving on 127.0.0.1:3000.
#
# This is the liveness component the reclassification above removed. It probes
# the app, not the compensating control, and over LOOPBACK -- which is exactly
# the address that is live in BOTH states: on the untouched box Next listens on
# 0.0.0.0:3000 (so 127.0.0.1 reaches it) and after the fix it is rebound to
# 127.0.0.1:3000. The reference control's `iptables ... ! -i lo -j DROP` spares
# loopback for the same reason nginx needs it. So this passes at baseline, as a
# regression check must, and it goes FALSE the moment the app is killed: no
# listener means the connection is refused and curl reports 000.
#
# Behavioural on purpose -- a `node` comm scan matches a zombie, an HTTP 200
# does not. Note this probe is NOT redundant with the proxy checks above: it
# distinguishes "the app died" from "nginx died", which a :80 probe alone cannot.
###############################################################################
APP_LIVE=0
APP_CODE=000
for i in 1 2 3 4 5; do
    APP_CODE=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:3000/" 2>/dev/null || echo 000)
    if [ "$APP_CODE" = "200" ]; then
        APP_LIVE=1
        break
    fi
    sleep 2
done

if [ "$APP_LIVE" = "1" ]; then
    record_reg nextjs_backend_alive 1 "Next.js backend serves / on 127.0.0.1:3000 (HTTP 200)"
else
    record_reg nextjs_backend_alive 0 "Next.js backend does not serve / on 127.0.0.1:3000 (HTTP $APP_CODE) - the application was destroyed"
fi

verify_finish
