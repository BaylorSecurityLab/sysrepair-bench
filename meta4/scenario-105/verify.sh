#!/bin/bash
# Scenario 105: Next.js Middleware Auth Bypass (CVE-2025-29927)
# Ground truth is BEHAVIORAL. Setting the internal header x-middleware-subrequest
# makes Next.js skip middleware, so /protected (normally 401) returns 200 with
# the secret. Vulnerable state: the app listens on 0.0.0.0:3000, so an attacker
# reaching the container's address gets the bypass. Remediation: rebind the app
# to loopback and front it with an nginx proxy that STRIPS the header.
set -u
IP=$(hostname -i 2>/dev/null | awk '{print $1}')
[ -z "$IP" ] && IP=127.0.0.1
HDR='x-middleware-subrequest: middleware'

###############################################################################
# PoC 1: the bypass must NOT work on the container's public address:3000
###############################################################################
BODY=$(curl -s -m 5 -H "$HDR" "http://$IP:3000/protected" 2>/dev/null || true)
CODE=$(curl -s -m 5 -o /dev/null -w '%{http_code}' -H "$HDR" "http://$IP:3000/protected" 2>/dev/null || echo 000)
if [ "$CODE" = "200" ] || printf '%s' "$BODY" | grep -qi 'Secret data'; then
    echo "FAIL [PoC]: middleware bypass works on public $IP:3000 (HTTP $CODE) — /protected exposed." >&2
    exit 1
fi
echo "PASS [PoC]: middleware bypass not reachable on public $IP:3000 ($CODE)."

###############################################################################
# PoC 2: through the nginx proxy on :80 the bypass header must be stripped, so
# /protected still returns 401 (not 200 / not the secret).
###############################################################################
CODE=$(curl -s -m 5 -o /dev/null -w '%{http_code}' -H "$HDR" "http://127.0.0.1:80/protected" 2>/dev/null || echo 000)
BODY=$(curl -s -m 5 -H "$HDR" "http://127.0.0.1:80/protected" 2>/dev/null || true)
if [ "$CODE" = "000" ]; then
    echo "FAIL [PoC]: nginx proxy not responding on :80 (proxy not deployed/started)." >&2
    exit 1
fi
if [ "$CODE" = "200" ] || printf '%s' "$BODY" | grep -qi 'Secret data'; then
    echo "FAIL [PoC]: bypass header not stripped by nginx — /protected returned $CODE." >&2
    exit 1
fi
echo "PASS [PoC]: nginx strips x-middleware-subrequest — /protected returns $CODE (not 200)."

###############################################################################
# Regression: the public landing page must still be served via nginx on :80
###############################################################################
for i in 1 2 3 4 5; do
    H=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:80/" 2>/dev/null || echo 000)
    if [ "$H" = "200" ]; then
        echo "PASS [Regression]: / returns 200 via nginx on port 80."
        exit 0
    fi
    sleep 2
done
echo "FAIL [Regression]: / not served via nginx on :80." >&2
exit 1
