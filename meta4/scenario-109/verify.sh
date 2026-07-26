#!/bin/bash
# Scenario 109: WebLogic Console URL Bypass (CVE-2020-14882)
# Ground truth is BEHAVIORAL against the LIVE public port 7001. The admin console
# (/console, incl. the %252e%252e URL-encoding bypass) must be unreachable from
# the network. Vulnerable state: the sim serves /console with no auth on
# 0.0.0.0:7001. Remediation: move the backend to loopback and put an nginx proxy
# on 7001 that denies /console.
set -u
IP=$(hostname -i 2>/dev/null | awk '{print $1}')
[ -z "$IP" ] && IP=127.0.0.1

code_of() { curl -s -m 5 -o /dev/null -w '%{http_code}' "http://$IP:7001$1" 2>/dev/null || echo 000; }
body_of() { curl -s -m 5 "http://$IP:7001$1" 2>/dev/null || true; }

# Wait for something to answer on 7001 (do NOT start it).
UP=0
for i in $(seq 1 20); do
    [ "$(code_of /)" != "000" ] && { UP=1; break; }
    sleep 2
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: nothing serving on 7001 (dead / not started)." >&2
    exit 1
fi

###############################################################################
# PoC 1: the URL-encoding bypass must be blocked (not 200, no console content)
###############################################################################
BP='/console/css/%252e%252e%252fconsole.portal'
CODE=$(code_of "$BP"); BODY=$(body_of "$BP")
if [ "$CODE" = "200" ] || printf '%s' "$BODY" | grep -qi 'WebLogic .*Console\|Administration Console'; then
    echo "FAIL [PoC]: URL-encoding bypass reachable on 7001 (HTTP $CODE) — console exposed." >&2
    exit 1
fi
echo "PASS [PoC]: URL-encoding bypass blocked ($CODE)."

###############################################################################
# PoC 2: direct /console must also be blocked
###############################################################################
CODE=$(code_of "/console"); BODY=$(body_of "/console")
if [ "$CODE" = "200" ] || printf '%s' "$BODY" | grep -qi 'Administration Console'; then
    echo "FAIL [PoC]: /console reachable on 7001 (HTTP $CODE) — console not blocked." >&2
    exit 1
fi
echo "PASS [PoC]: /console blocked ($CODE)."

###############################################################################
# Regression: non-console paths must still be served via the proxy
###############################################################################
for i in 1 2 3 4 5; do
    if [ "$(code_of /)" = "200" ]; then
        echo "PASS [Regression]: WebLogic root path served on 7001 (HTTP 200)."
        exit 0
    fi
    sleep 2
done
echo "FAIL [Regression]: root path not served on 7001." >&2
exit 1
