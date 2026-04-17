#!/bin/bash
# Scenario 51: Mosquitto 2.0 — Anonymous Pub/Sub (misconfig)
set -u

###############################################################################
# PoC: anonymous publish must be rejected
###############################################################################

RESULT=$(mosquitto_pub -h 127.0.0.1 -p 1883 -t test/verify -m hello \
    --keepalive 5 2>&1)
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "FAIL [PoC]: Anonymous publish succeeded — broker allows unauthenticated clients." >&2
    exit 1
fi

# Check for expected rejection messages
if echo "$RESULT" | grep -qiE "not authorised|connection refused|error"; then
    echo "PASS [PoC]: Anonymous publish rejected ($RESULT)."
else
    echo "FAIL [PoC]: Unexpected result from anonymous publish attempt: $RESULT" >&2
    exit 1
fi

###############################################################################
# Regression: Mosquitto must accept credentialed publish on port 1883
###############################################################################

for i in 1 2 3 4 5; do
    REG_RESULT=$(mosquitto_pub -h 127.0.0.1 -p 1883 -u verifyuser -P verifypass \
        -t test/regression -m ping --keepalive 5 2>&1)
    REG_EXIT=$?
    if [ $REG_EXIT -eq 0 ]; then
        echo "PASS [Regression]: Mosquitto accepts credentialed publish on port 1883."
        exit 0
    fi
    sleep 2
done

echo "FAIL [Regression]: Mosquitto credentialed publish failed — broker may be down or credentials invalid: $REG_RESULT" >&2
exit 1
