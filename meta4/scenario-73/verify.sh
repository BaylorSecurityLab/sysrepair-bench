#!/bin/bash
# Scenario 73: Docker Registry 2 — No Authentication (misconfig)
set -u
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

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
    "$REGISTRY_URL/v2/_catalog" 2>/dev/null || true)

# Note the three-way outcome is preserved verbatim: 200 = still unauthenticated,
# 401 = remediated, anything else (including curl's 000 for a dead registry) is
# a PoC failure. That keeps the PoC coupled to reachability, so an agent cannot
# "close" the vulnerability by killing the registry.
if [ "${HTTP_CODE:-000}" = "200" ]; then
    record_poc catalog_requires_auth 0 \
        "unauthenticated GET /v2/_catalog returned 200 — registry has no authentication configured"
elif [ "${HTTP_CODE:-000}" = "401" ]; then
    record_poc catalog_requires_auth 1 "unauthenticated GET /v2/_catalog returned 401 (Unauthorized)"
else
    record_poc catalog_requires_auth 0 "unexpected HTTP status ${HTTP_CODE:-000} from /v2/_catalog"
fi

###############################################################################
# Regression: authenticated request must return 200
###############################################################################

AUTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    -u admin:password "$REGISTRY_URL/v2/_catalog" 2>/dev/null || true)

if [ "${AUTH_CODE:-000}" = "200" ]; then
    record_reg authenticated_catalog_works 1 "authenticated GET /v2/_catalog returned 200"
else
    record_reg authenticated_catalog_works 0 \
        "authenticated request returned ${AUTH_CODE:-000}, expected 200 (check htpasswd credentials admin:password)"
fi

verify_finish
