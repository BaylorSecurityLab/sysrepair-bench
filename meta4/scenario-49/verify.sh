#!/bin/bash
# Scenario 49: ActiveMQ 6.1.0 — Jolokia/REST API Exposed (CVE-2024-32114)
set -u

###############################################################################
# PoC: /api/message without credentials must return 401
###############################################################################

HTTP_CODE=""
for i in 1 2 3 4 5; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8161/api/message 2>/dev/null)
    if [ "$HTTP_CODE" = "200" ]; then
        echo "FAIL [PoC]: /api/message accessible without authentication (HTTP 200)." >&2
        exit 1
    elif [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
        echo "PASS [PoC]: /api/message requires authentication (HTTP $HTTP_CODE)."
        break
    fi
    sleep 3
done

# Final check if we never got a definitive answer
if [ "$HTTP_CODE" != "401" ] && [ "$HTTP_CODE" != "403" ]; then
    echo "FAIL [PoC]: Could not confirm /api/message requires authentication (HTTP $HTTP_CODE)." >&2
    exit 1
fi

###############################################################################
# Regression: Web console on 8161 must still be reachable
###############################################################################

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8161/ 2>/dev/null)
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "401" ]; then
    echo "PASS [Regression]: ActiveMQ web console responding on port 8161 (HTTP $HTTP_CODE)."
    exit 0
fi

echo "FAIL [Regression]: ActiveMQ web console not responding on port 8161 (HTTP $HTTP_CODE)." >&2
exit 1
