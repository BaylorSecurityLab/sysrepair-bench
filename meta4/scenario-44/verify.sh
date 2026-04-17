#!/bin/bash
# Scenario 44: Elasticsearch 7.10.1 — X-Pack Security Disabled (misconfig)
set -u

ES_URL="http://localhost:9200"

###############################################################################
# PoC: unauthenticated request to the root endpoint must return 401
###############################################################################

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${ES_URL}/" 2>/dev/null)

if [ "$HTTP_CODE" = "200" ]; then
    echo "FAIL [PoC]: Elasticsearch returned HTTP 200 for unauthenticated request — X-Pack security is disabled." >&2
    exit 1
fi

if [ "$HTTP_CODE" != "401" ]; then
    echo "FAIL [PoC]: Elasticsearch returned unexpected HTTP ${HTTP_CODE} (expected 401 with security enabled)." >&2
    exit 1
fi

echo "PASS [PoC]: Elasticsearch rejects unauthenticated access with HTTP 401."

###############################################################################
# Regression: cluster health endpoint must be reachable (authenticated)
###############################################################################

# Use the elastic superuser; password must be supplied via ELASTIC_PASSWORD env
ELASTIC_PASSWORD="${ELASTIC_PASSWORD:-changeme}"

for i in 1 2 3 4 5 6 7 8; do
    HEALTH=$(curl -s -u "elastic:${ELASTIC_PASSWORD}" \
        "${ES_URL}/_cluster/health" 2>/dev/null | grep -oE '"status"\s*:\s*"[^"]+"')
    if echo "$HEALTH" | grep -qE '"(green|yellow)"'; then
        echo "PASS [Regression]: Elasticsearch cluster health reachable with credentials (${HEALTH})."
        exit 0
    fi
    sleep 3
done

echo "FAIL [Regression]: Elasticsearch cluster health endpoint not reachable after remediation." >&2
exit 1
