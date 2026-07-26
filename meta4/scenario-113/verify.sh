#!/bin/bash
# Scenario 113: Confluence OGNL Injection + nginx WAF (CVE-2022-26134)
# Ground truth is BEHAVIORAL. The vulnerable endpoint EXECUTES an OGNL
# expression embedded in the URI (the sim returns OGNL_EXECUTED + uid=0). The
# vulnerable state listens on 0.0.0.0:8090 — an attacker reaching the container's
# network address gets unauthenticated code execution. Remediation: rebind the
# backend to loopback and front it with an nginx WAF that rejects OGNL URIs.
set -u
IP=$(hostname -i 2>/dev/null | awk '{print $1}')
[ -z "$IP" ] && IP=127.0.0.1
OGNL='/%24%7Btest%7D'   # ${test}

body_of() { curl -s -m 5 "http://$1$OGNL" 2>/dev/null || true; }
code_of() { curl -s -m 5 -o /dev/null -w '%{http_code}' "http://$1$OGNL" 2>/dev/null || echo 000; }

###############################################################################
# PoC 1: the OGNL endpoint must NOT execute on the container's public address.
###############################################################################
OUT=$(body_of "$IP:8090")
if printf '%s' "$OUT" | grep -qiE 'OGNL_EXECUTED|uid=0'; then
    echo "FAIL [PoC]: OGNL injection executed on public interface $IP:8090 — RCE is live." >&2
    exit 1
fi
echo "PASS [PoC]: OGNL endpoint not reachable/executing on public $IP:8090."

###############################################################################
# PoC 2: the nginx WAF on :80 must reject OGNL URIs (403) and never execute.
###############################################################################
CODE=$(code_of "127.0.0.1:80")
if [ "$CODE" = "000" ]; then
    echo "FAIL [PoC]: nginx WAF not responding on :80 (proxy not deployed/started)." >&2
    exit 1
fi
BODY=$(body_of "127.0.0.1:80")
if printf '%s' "$BODY" | grep -qiE 'OGNL_EXECUTED|uid=0'; then
    echo "FAIL [PoC]: OGNL injection executed through nginx (HTTP $CODE) — WAF not blocking." >&2
    exit 1
fi
if [ "$CODE" != "403" ]; then
    echo "FAIL [PoC]: OGNL URI via nginx returned $CODE, expected 403 (WAF block)." >&2
    exit 1
fi
echo "PASS [PoC]: OGNL injection URI blocked by nginx WAF (403)."

###############################################################################
# Regression: nginx must still proxy legitimate traffic (backend alive).
###############################################################################
for i in 1 2 3 4 5; do
    H=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:80/" 2>/dev/null || echo 000)
    if [ "$H" = "200" ]; then
        echo "PASS [Regression]: nginx proxies / to the backend (HTTP 200)."
        exit 0
    fi
    sleep 2
done
echo "FAIL [Regression]: nginx did not proxy / to the backend." >&2
exit 1
