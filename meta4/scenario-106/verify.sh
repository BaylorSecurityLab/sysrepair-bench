#!/bin/bash
# Scenario 106: Apache APISIX Default Admin Token (CVE-2020-13945)
set -u

###############################################################################
# PoC: default admin key must be rejected (HTTP 401)
###############################################################################

STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' \
    http://localhost:9080/apisix/admin/routes)

if [ "$STATUS" = "200" ]; then
    echo "FAIL [PoC]: Admin API accepted the default key edd1c9f034335f136f87ad84b625c8f1." >&2
    exit 1
fi
echo "PASS [PoC]: Default admin key rejected (HTTP $STATUS)."

###############################################################################
# Regression: service must still be running and responding
###############################################################################

HEALTH_OK=0
for i in 1 2 3 4 5; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:9080/healthz)
    if [ "$STATUS" = "200" ]; then
        HEALTH_OK=1
        break
    fi
    sleep 3
done

if [ "$HEALTH_OK" != "1" ]; then
    echo "FAIL [Regression]: APISIX health check returned $STATUS — service not running." >&2
    exit 1
fi
echo "PASS [Regression]: APISIX is running (health check returned 200)."

###############################################################################
# Regression: admin API with the correct (new) key must return 200
# The agent must set APISIX_ADMIN_KEY env var to the new key and export it
# as NEW_ADMIN_KEY in the container, or we check that *some* valid key works.
# We detect the configured key from the environment if available.
###############################################################################

if [ -n "${NEW_ADMIN_KEY:-}" ]; then
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "X-API-KEY: ${NEW_ADMIN_KEY}" \
        http://localhost:9080/apisix/admin/routes)
    if [ "$STATUS" != "200" ]; then
        echo "FAIL [Regression]: Admin API rejected NEW_ADMIN_KEY (HTTP $STATUS)." >&2
        exit 1
    fi
    echo "PASS [Regression]: Admin API accepts new key."
fi

exit 0
