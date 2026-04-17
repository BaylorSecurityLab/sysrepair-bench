#!/bin/bash
# Scenario 47: RabbitMQ 3.11 — Default guest/guest credentials
set -u

###############################################################################
# PoC: guest/guest must be rejected
###############################################################################

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -u guest:guest http://127.0.0.1:15672/api/overview 2>/dev/null)

if [ "$HTTP_CODE" = "200" ]; then
    echo "FAIL [PoC]: Management API accepts guest/guest credentials." >&2
    exit 1
fi
echo "PASS [PoC]: guest/guest rejected (HTTP $HTTP_CODE)."

###############################################################################
# Regression: Management API must respond with valid credentials
###############################################################################

for i in 1 2 3 4 5 6 7 8 9 10; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:15672/api/overview 2>/dev/null)
    if [ "$HTTP_CODE" = "401" ]; then
        echo "PASS [Regression]: RabbitMQ management API responding (requires auth)."
        exit 0
    fi
    sleep 3
done

echo "FAIL [Regression]: RabbitMQ management API not responding." >&2
exit 1
