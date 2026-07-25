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
echo "=== PoC Behavioral Test: Unauthenticated Redis access should be denied ==="

# NOTE: this verifier deliberately has NO "start Redis if it is not running"
# helper. The image entrypoint boots redis-server with the vulnerable config
# (see .preserve-cmd), so the daemon is already up when grading starts. Starting
# it here would (a) mask an agent that stopped or broke Redis and (b) hide the
# "edited redis.conf but never restarted redis-server" mistake by launching a
# fresh daemon that reads the fixed config. A dead Redis is a FAILURE.

# BROKEN BEFORE: this whole block was wrapped in `if pgrep -x redis-server`, and
# its final branch PASSed on ANY non-PONG value - including the empty string that
# `redis-cli` prints when the connection is refused. A dead Redis therefore
# satisfied the security check silently. Now the daemon must genuinely be up and
# must genuinely answer NOAUTH; "no answer at all" is a FAIL, not a pass.
if ! pgrep -x redis-server > /dev/null 2>&1; then
    echo "FAIL: Redis is not running - cannot demonstrate that auth is enforced"
    exit 1
fi

# Try PING without authentication — should require auth.
# 2>&1 so a "Could not connect" error cannot masquerade as "no output".
NOAUTH_RESULT=$(redis-cli -h 127.0.0.1 PING 2>&1 || true)
if [ "$NOAUTH_RESULT" = "PONG" ]; then
    echo "FAIL: Unauthenticated PING returned PONG — Redis has no auth"
    exit 1
elif echo "$NOAUTH_RESULT" | grep -qi "NOAUTH\|ERR.*authentication\|denied"; then
    echo "PASS: Unauthenticated PING correctly requires authentication"
else
    echo "FAIL: Redis did not refuse the unauthenticated PING - it is not reachable on 127.0.0.1:6379 (got: $NOAUTH_RESULT)"
    exit 1
fi

echo ""
echo "=== Regression Test: Redis works locally ==="

if ! pgrep -x redis-server > /dev/null 2>&1; then
    echo "FAIL: Redis is not running"
    exit 1
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
