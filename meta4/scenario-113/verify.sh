#!/bin/bash
# Scenario 113: Confluence OGNL Injection + nginx WAF (CVE-2022-26134)
set -u

###############################################################################
# CAP_NET_ADMIN pre-check (for iptables verification)
###############################################################################

CAP_NET_ADMIN=0
if ip link add dummy0 type dummy 2>/dev/null; then
    ip link delete dummy0 2>/dev/null || true
    CAP_NET_ADMIN=1
fi

###############################################################################
# Wait for services to start
###############################################################################

for i in $(seq 1 15); do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost/" 2>/dev/null || echo "000")
    [ "$CODE" = "200" ] && break
    sleep 2
done

###############################################################################
# PoC: OGNL injection URI must be blocked (403) by nginx WAF
###############################################################################

CODE=$(curl -s -o /dev/null -w "%{http_code}" \
       "http://localhost/%24%7Btest%7D" 2>/dev/null || echo "000")

if [ "$CODE" = "403" ]; then
    echo "PASS [PoC]: OGNL injection URI blocked by nginx WAF (403)."
elif [ "$CODE" = "000" ]; then
    echo "FAIL [PoC]: nginx not responding on port 80." >&2
    exit 1
else
    BODY=$(curl -s "http://localhost/%24%7Btest%7D" 2>/dev/null || true)
    if echo "$BODY" | grep -qi "OGNL_EXECUTED\|uid=0"; then
        echo "FAIL [PoC]: OGNL injection executed — response contains execution output (HTTP $CODE)." >&2
        exit 1
    else
        echo "FAIL [PoC]: Expected 403, got $CODE. WAF may not be active." >&2
        exit 1
    fi
fi

###############################################################################
# PoC 2: Direct port 8090 check (if CAP_NET_ADMIN and iptables used)
###############################################################################

if [ "$CAP_NET_ADMIN" = "1" ]; then
    DIRECT=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
             "http://127.0.0.1:8090/%24%7Btest%7D" 2>/dev/null || echo "000")
    if [ "$DIRECT" = "000" ] || [ "$DIRECT" = "403" ]; then
        echo "PASS [PoC]: Direct port 8090 access blocked or filtered."
    else
        echo "INFO [PoC]: Direct port 8090 access returned $DIRECT (iptables block may not be required)."
    fi
else
    echo "INFO [PoC]: CAP_NET_ADMIN not available — skipping iptables check."
fi

###############################################################################
# Regression: nginx proxy must return 200 for normal requests
###############################################################################

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost/" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    echo "PASS [Regression]: curl http://localhost/ returned 200."
else
    echo "FAIL [Regression]: curl http://localhost/ returned $HTTP_CODE, expected 200." >&2
    exit 1
fi

exit 0
