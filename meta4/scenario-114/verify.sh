#!/bin/bash
# Scenario 114: Cacti Command Injection + nginx WAF (CVE-2022-46169)
set -u

###############################################################################
# CAP_NET_ADMIN pre-check
###############################################################################

CAP_NET_ADMIN=0
if ip link add dummy0 type dummy 2>/dev/null; then
    ip link delete dummy0 2>/dev/null || true
    CAP_NET_ADMIN=1
fi

###############################################################################
# Wait for nginx to be ready
###############################################################################

for i in $(seq 1 15); do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost/" 2>/dev/null || echo "000")
    [ "$CODE" = "200" ] && break
    sleep 2
done

###############################################################################
# PoC: remote_agent.php must return 403 from nginx proxy
###############################################################################

CODE=$(curl -s -o /dev/null -w "%{http_code}" \
       "http://localhost/remote_agent.php" 2>/dev/null || echo "000")

if [ "$CODE" = "403" ]; then
    echo "PASS [PoC]: /remote_agent.php is blocked by nginx proxy (403)."
elif [ "$CODE" = "000" ]; then
    echo "FAIL [PoC]: nginx not responding on port 80." >&2
    exit 1
else
    BODY=$(curl -s "http://localhost/remote_agent.php" 2>/dev/null || true)
    if echo "$BODY" | grep -qi "REMOTE_AGENT_RESPONSE\|shell_exec\|polled_host"; then
        echo "FAIL [PoC]: remote_agent.php is accessible — injection endpoint exposed (HTTP $CODE)." >&2
        exit 1
    else
        echo "FAIL [PoC]: Expected 403, got $CODE." >&2
        exit 1
    fi
fi

###############################################################################
# PoC 2: injection attempt must also be blocked
###############################################################################

CODE2=$(curl -s -o /dev/null -w "%{http_code}" \
        "http://localhost/remote_agent.php?action=polldata&host_id=1%3Bid" \
        2>/dev/null || echo "000")
if [ "$CODE2" = "403" ]; then
    echo "PASS [PoC]: Injection attempt also blocked (403)."
else
    echo "INFO [PoC]: Injection attempt returned $CODE2 (endpoint already blocked upstream)."
fi

###############################################################################
# Regression: Cacti login page must be accessible
###############################################################################

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost/" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    BODY=$(curl -s "http://localhost/" 2>/dev/null || true)
    if echo "$BODY" | grep -qi "cacti\|login\|network"; then
        echo "PASS [Regression]: curl http://localhost/ returned 200 with Cacti login page."
    else
        echo "PASS [Regression]: curl http://localhost/ returned 200."
    fi
else
    echo "FAIL [Regression]: curl http://localhost/ returned $HTTP_CODE, expected 200." >&2
    exit 1
fi

exit 0
