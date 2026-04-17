#!/bin/bash
# Scenario 58: PowerDNS Auth 4.8 — Empty API Key (misconfig)
set -u

###############################################################################
# PoC: API must return 401 without a key
###############################################################################

for i in 1 2 3 4 5 6 7 8 9 10; do
    HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8081/api/v1/servers 2>/dev/null)
    if [ "$HTTP_CODE" = "401" ]; then
        echo "PASS [PoC]: API returns 401 Unauthorized without an API key."
        break
    elif [ "$HTTP_CODE" = "200" ]; then
        echo "FAIL [PoC]: API returned 200 without authentication — api-key is still empty or missing." >&2
        exit 1
    elif [ "$HTTP_CODE" = "000" ]; then
        # Server not yet ready
        sleep 2
        continue
    else
        echo "FAIL [PoC]: Unexpected HTTP status '$HTTP_CODE' from API." >&2
        exit 1
    fi
done

if [ "$HTTP_CODE" = "000" ]; then
    echo "FAIL [PoC]: API did not respond after retries." >&2
    exit 1
fi

###############################################################################
# Config check: api-key must not be empty
###############################################################################

if grep -E '^api-key=' /etc/powerdns/pdns.conf 2>/dev/null | grep -q 'api-key=$'; then
    echo "FAIL [PoC]: pdns.conf has an empty api-key." >&2
    exit 1
fi
echo "PASS [PoC]: api-key is not empty in pdns.conf."

###############################################################################
# Regression: API works with the correct key
###############################################################################

API_KEY=$(grep -E '^api-key=' /etc/powerdns/pdns.conf 2>/dev/null | cut -d= -f2-)

if [ -z "$API_KEY" ]; then
    echo "FAIL [Regression]: Cannot read api-key from pdns.conf." >&2
    exit 1
fi

for i in 1 2 3 4 5 6 7 8 9 10; do
    HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        -H "X-API-Key: ${API_KEY}" \
        http://localhost:8081/api/v1/servers 2>/dev/null)
    if [ "$HTTP_CODE" = "200" ]; then
        echo "PASS [Regression]: API returns 200 with correct X-API-Key."
        exit 0
    fi
    sleep 2
done

echo "FAIL [Regression]: API did not return 200 with correct key after remediation." >&2
exit 1
