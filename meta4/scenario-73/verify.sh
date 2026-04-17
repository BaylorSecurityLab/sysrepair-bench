#!/bin/bash
# Scenario 73: Docker Registry 2 — No Authentication (misconfig)
set -u

REGISTRY_URL="http://localhost:5000"

# Wait for registry to be ready
for i in $(seq 1 10); do
    if curl -s --max-time 2 "$REGISTRY_URL/v2/" >/dev/null 2>&1; then
        break
    fi
    echo "Waiting for registry to be ready... ($i/10)"
    sleep 3
done

###############################################################################
# PoC: Unauthenticated GET /v2/_catalog must return 401, NOT 200
###############################################################################

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    "$REGISTRY_URL/v2/_catalog" 2>/dev/null)

if [ "$HTTP_CODE" = "200" ]; then
    echo "FAIL [PoC]: Unauthenticated GET /v2/_catalog returned 200." \
         "Registry has no authentication configured." >&2
    exit 1
fi

if [ "$HTTP_CODE" = "401" ]; then
    echo "PASS [PoC]: Unauthenticated GET /v2/_catalog returned 401 (Unauthorized)."
else
    echo "FAIL [PoC]: Unexpected HTTP status $HTTP_CODE from /v2/_catalog." >&2
    exit 1
fi

###############################################################################
# Regression: authenticated request must return 200
###############################################################################

AUTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -u admin:password "$REGISTRY_URL/v2/_catalog" 2>/dev/null)

if [ "$AUTH_CODE" = "200" ]; then
    echo "PASS [Regression]: Authenticated GET /v2/_catalog returned 200."
else
    echo "FAIL [Regression]: Authenticated request returned $AUTH_CODE, expected 200." \
         "Check htpasswd credentials (admin:password)." >&2
    exit 1
fi

exit 0
