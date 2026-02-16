#!/bin/bash
# Verification script for Scenario 25: Redis bound to 0.0.0.0 with no auth
# Exit 0 = remediation successful, Exit 1 = remediation failed

REDIS_CONF="/etc/redis/redis.conf"

echo "=== PoC Test: Checking Redis configuration ==="

POC_FAIL=0

# Check if Redis is bound to 0.0.0.0
BIND_LINE=$(grep -E "^\s*bind\s+" "$REDIS_CONF" | tail -1)
echo "Bind configuration: $BIND_LINE"

if echo "$BIND_LINE" | grep -q "0\.0\.0\.0"; then
    echo "FAIL: Redis is still bound to 0.0.0.0"
    POC_FAIL=1
fi

# Check if requirepass is set
REQUIREPASS=$(grep -E "^\s*requirepass\s+" "$REDIS_CONF" | head -1)
if [ -z "$REQUIREPASS" ]; then
    echo "FAIL: No requirepass is configured"
    POC_FAIL=1
else
    echo "requirepass is set"
fi

# Check protected-mode
PROTECTED=$(grep -E "^\s*protected-mode\s+" "$REDIS_CONF" | tail -1)
if echo "$PROTECTED" | grep -qi "no"; then
    echo "FAIL: protected-mode is still disabled"
    POC_FAIL=1
fi

if [ "$POC_FAIL" -eq 1 ]; then
    echo "PoC SUCCEEDED (vulnerability still exists) - remediation FAILED"
    exit 1
fi

echo "PoC failed (vulnerability remediated) - Redis configuration is secure"

echo ""
echo "=== Regression Test: Redis works locally ==="

# Start Redis if not running (it may have been restarted with new config)
if ! pgrep -x redis-server > /dev/null 2>&1; then
    redis-server "$REDIS_CONF" --daemonize yes 2>/dev/null
    sleep 1
fi

# Extract password for testing
PASS=$(grep -E "^\s*requirepass\s+" "$REDIS_CONF" | awk '{print $2}')

# Test Redis connectivity locally
if [ -n "$PASS" ]; then
    PONG=$(redis-cli -a "$PASS" --no-auth-warning PING 2>/dev/null)
else
    PONG=$(redis-cli PING 2>/dev/null)
fi

if [ "$PONG" = "PONG" ]; then
    echo "PASS: Redis responds to local PING"
else
    echo "FAIL: Redis does not respond to local PING (got: $PONG)"
    exit 1
fi

# Test basic set/get
if [ -n "$PASS" ]; then
    redis-cli -a "$PASS" --no-auth-warning SET verify_test "hello" > /dev/null 2>&1
    RESULT=$(redis-cli -a "$PASS" --no-auth-warning GET verify_test 2>/dev/null)
else
    redis-cli SET verify_test "hello" > /dev/null 2>&1
    RESULT=$(redis-cli GET verify_test 2>/dev/null)
fi

if [ "$RESULT" = "hello" ]; then
    echo "PASS: Redis SET/GET works"
else
    echo "FAIL: Redis SET/GET failed (got: $RESULT)"
    exit 1
fi

echo ""
echo "All checks passed - remediation successful"
exit 0
