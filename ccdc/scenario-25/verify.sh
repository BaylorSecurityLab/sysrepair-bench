#!/bin/bash
# Verification script for Scenario 25: Redis bound to 0.0.0.0 with no auth
# Exit 0 = every check passed, Exit 1 = at least one check failed
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "locked Redis down but killed redis-server" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

REDIS_CONF="/etc/redis/redis.conf"

echo "=== PoC Test: Checking Redis configuration ==="

# Check if Redis is bound to 0.0.0.0
BIND_LINE=$(grep -E "^\s*bind\s+" "$REDIS_CONF" | tail -1)
echo "Bind configuration: $BIND_LINE"

if echo "$BIND_LINE" | grep -q "0\.0\.0\.0"; then
    record_poc redis_not_bound_to_all_interfaces 0 "Redis is still bound to 0.0.0.0"
else
    record_poc redis_not_bound_to_all_interfaces 1
fi

# Check if requirepass is set
REQUIREPASS=$(grep -E "^\s*requirepass\s+" "$REDIS_CONF" | head -1)
if [ -z "$REQUIREPASS" ]; then
    record_poc redis_requirepass_configured 0 "no requirepass is configured"
else
    record_poc redis_requirepass_configured 1 "requirepass is set"
fi

# Check protected-mode
PROTECTED=$(grep -E "^\s*protected-mode\s+" "$REDIS_CONF" | tail -1)
if echo "$PROTECTED" | grep -qi "no"; then
    record_poc redis_protected_mode_enabled 0 "protected-mode is still disabled"
else
    record_poc redis_protected_mode_enabled 1
fi

echo ""
echo "=== PoC Behavioral Test: Unauthenticated Redis access should be denied ==="

# NOTE: this verifier deliberately has NO "start Redis if it is not running"
# helper. The image entrypoint boots redis-server with the vulnerable config
# (see .preserve-cmd), so the daemon is already up when grading starts. Starting
# it here would (a) mask an agent that stopped or broke Redis and (b) hide the
# "edited redis.conf but never restarted redis-server" mistake by launching a
# fresh daemon that reads the fixed config. A dead Redis is a FAILURE — recorded
# as the redis_running regression check, since a dead daemon is a service-health
# fact rather than evidence the vulnerability was closed.

# BROKEN BEFORE: this whole block was wrapped in `if pgrep -x redis-server`, and
# its final branch PASSed on ANY non-PONG value - including the empty string that
# `redis-cli` prints when the connection is refused. A dead Redis therefore
# satisfied the security check silently. Now the daemon must genuinely be up and
# must genuinely answer NOAUTH; "no answer at all" is a FAIL, not a pass.
if pgrep -x redis-server > /dev/null 2>&1; then
    record_reg redis_running 1
    REDIS_UP=1
else
    record_reg redis_running 0 "Redis is not running"
    REDIS_UP=0
fi

if [ "$REDIS_UP" = "1" ]; then
    # Try PING without authentication — should require auth.
    # 2>&1 so a "Could not connect" error cannot masquerade as "no output".
    NOAUTH_RESULT=$(redis-cli -h 127.0.0.1 PING 2>&1 || true)
    if [ "$NOAUTH_RESULT" = "PONG" ]; then
        record_poc unauthenticated_ping_refused 0 "unauthenticated PING returned PONG - Redis has no auth"
    elif echo "$NOAUTH_RESULT" | grep -qi "NOAUTH\|ERR.*authentication\|denied"; then
        record_poc unauthenticated_ping_refused 1 "unauthenticated PING correctly requires authentication"
    else
        record_poc unauthenticated_ping_refused 0 "Redis did not refuse the unauthenticated PING - it is not reachable on 127.0.0.1:6379 (got: $NOAUTH_RESULT)"
    fi
else
    echo "  [skip] Redis is not running - the unauthenticated-access PoC cannot be probed"
fi

echo ""
echo "=== Regression Test: Redis works locally ==="

# Extract password for testing. NOTE: this must NOT be called PASS — verifylib
# defines PASS=0 as the success exit code and verify_finish uses it.
REDIS_PASS=$(grep -E "^\s*requirepass\s+" "$REDIS_CONF" | awk '{print $2}')

# Test Redis connectivity locally
if [ -n "$REDIS_PASS" ]; then
    PONG=$(redis-cli -a "$REDIS_PASS" --no-auth-warning PING 2>/dev/null)
else
    PONG=$(redis-cli PING 2>/dev/null)
fi

if [ "$PONG" = "PONG" ]; then
    record_reg redis_local_ping 1 "Redis responds to local PING"
else
    record_reg redis_local_ping 0 "Redis does not respond to local PING (got: $PONG)"
fi

# Test basic set/get
if [ -n "$REDIS_PASS" ]; then
    redis-cli -a "$REDIS_PASS" --no-auth-warning SET verify_test "hello" > /dev/null 2>&1
    RESULT=$(redis-cli -a "$REDIS_PASS" --no-auth-warning GET verify_test 2>/dev/null)
else
    redis-cli SET verify_test "hello" > /dev/null 2>&1
    RESULT=$(redis-cli GET verify_test 2>/dev/null)
fi

if [ "$RESULT" = "hello" ]; then
    record_reg redis_set_get 1 "Redis SET/GET works"
else
    record_reg redis_set_get 0 "Redis SET/GET failed (got: $RESULT)"
fi

verify_finish
