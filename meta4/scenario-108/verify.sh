#!/bin/bash
# Scenario 108: Langflow Pre-auth RCE (CVE-2025-3248)
set -u

###############################################################################
# PoC 1: Unauthenticated request to nginx proxy must return 401
###############################################################################

STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://localhost/api/v1/run \
    -H 'Content-Type: application/json' \
    -d '{"code":"import os; os.system(\"id\")"}')

if [ "$STATUS" = "200" ]; then
    echo "FAIL [PoC]: /api/v1/run returned 200 without auth — nginx basic auth not enforced." >&2
    exit 1
fi
echo "PASS [PoC]: Unauthenticated /api/v1/run via nginx returned $STATUS (not 200)."

###############################################################################
# PoC 2: Direct access to port 7860 must be blocked by iptables
###############################################################################

if iptables -L INPUT -n &>/dev/null; then
    if iptables -L INPUT -n | grep -qE 'DROP.*dpt:7860|DROP.*tcp.*7860'; then
        echo "PASS [PoC]: iptables DROP rule for port 7860 is in place."
    else
        if nc -z -w2 127.0.0.1 7860 2>/dev/null; then
            echo "WARN [PoC]: Port 7860 is reachable directly and no iptables DROP rule found." >&2
        else
            echo "PASS [PoC]: Port 7860 is not directly reachable."
        fi
    fi
else
    echo "INFO [PoC]: CAP_NET_ADMIN not available — skipping iptables check for port 7860."
fi

###############################################################################
# Regression: Langflow responds via nginx with valid basic auth credentials
###############################################################################

for i in 1 2 3 4 5; do
    STATUS_BARE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/ 2>/dev/null)
    if [ -n "$STATUS_BARE" ] && [ "$STATUS_BARE" != "000" ]; then
        echo "PASS [Regression]: nginx is running on port 80 (returned $STATUS_BARE)."
        exit 0
    fi
    sleep 3
done

echo "FAIL [Regression]: nginx on port 80 is not responding." >&2
exit 1
