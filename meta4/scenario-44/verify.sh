#!/bin/bash
# Scenario 44: Elasticsearch 7.10.1 — X-Pack Security Disabled (misconfig)
#
# PoC (DYNAMIC, against the LIVE node on :9200): an unauthenticated request to
# the root endpoint must be REJECTED (401).  A 200 means security is off on the
# running node — including the "flipped the config but never restarted" case.
# Regression: an AUTHENTICATED request (elastic:changeme) must succeed.
set -u

ES_URL="http://localhost:9200"
ELASTIC_PASSWORD="${ELASTIC_PASSWORD:-changeme}"

###############################################################################
# Wait until ES answers at all, so a slow boot is not mistaken for "fixed" and
# the PoC tests the real running node.
###############################################################################
CODE="000"
for i in $(seq 1 60); do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" "${ES_URL}/" 2>/dev/null)
    [ "$CODE" != "000" ] && break
    sleep 2
done
if [ "$CODE" = "000" ]; then
    echo "FAIL [Regression]: Elasticsearch not reachable on 9200 (service down)." >&2
    exit 1
fi

###############################################################################
# PoC (DYNAMIC): unauthenticated request must be denied
###############################################################################
if [ "$CODE" = "200" ]; then
    echo "FAIL [PoC]: unauthenticated GET / returned 200 — X-Pack security is disabled on the live node." >&2
    exit 1
fi
if [ "$CODE" != "401" ]; then
    echo "FAIL [PoC]: unauthenticated GET / returned unexpected HTTP ${CODE} (expected 401 with security enabled)." >&2
    exit 1
fi
echo "PASS [PoC]: Elasticsearch rejects unauthenticated access with HTTP 401."

###############################################################################
# Regression: authenticated cluster health must be reachable
###############################################################################
for i in $(seq 1 20); do
    HEALTH=$(curl -s -u "elastic:${ELASTIC_PASSWORD}" \
        "${ES_URL}/_cluster/health" 2>/dev/null | grep -oE '"status"[[:space:]]*:[[:space:]]*"[^"]+"')
    if echo "$HEALTH" | grep -qE '"(green|yellow)"'; then
        echo "PASS [Regression]: Elasticsearch cluster health reachable with credentials (${HEALTH})."
        exit 0
    fi
    sleep 3
done

echo "FAIL [Regression]: Elasticsearch cluster health endpoint not reachable with elastic:${ELASTIC_PASSWORD} after remediation." >&2
exit 1
