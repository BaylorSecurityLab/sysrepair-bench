#!/bin/bash
# Scenario 93: Jupyter Notebook — No Token Authentication (misconfig)
set -u

###############################################################################
# PoC: unauthenticated /api/contents must return 401 or 403
###############################################################################

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/api/contents 2>/dev/null || echo "000")

if echo "$HTTP_CODE" | grep -qE '^(401|403)$'; then
    echo "PASS [PoC]: Unauthenticated /api/contents returns HTTP $HTTP_CODE."
else
    echo "FAIL [PoC]: /api/contents returned HTTP $HTTP_CODE (expected 401 or 403)." >&2
    exit 1
fi

###############################################################################
# Regression: Jupyter must still be running on port 8888
###############################################################################

for i in 1 2 3 4 5; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/login 2>/dev/null || echo "000")
    if echo "$STATUS" | grep -qE '^(200|302|301)$'; then
        echo "PASS [Regression]: Jupyter is reachable on port 8888 (HTTP $STATUS)."
        exit 0
    fi
    sleep 3
done

echo "FAIL [Regression]: Jupyter not reachable on port 8888 after remediation." >&2
exit 1
