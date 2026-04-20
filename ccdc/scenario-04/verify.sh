#!/usr/bin/env bash
###############################################################################
# Scenario 04 - Verification Script
# SSH X11 Forwarding + High MaxAuthTries (CWE-307)
#
# PoC Test:        Verify X11Forwarding is off, MaxAuthTries <= 6
# Regression Test: Verify SSH still works normally
#
# Exit 0 = remediation successful (PoC fails AND functionality works)
# Exit 1 = remediation failed
###############################################################################

set -euo pipefail

PASS=0
FAIL=1

# Install test dependencies if not present
if ! command -v sshpass &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq sshpass openssh-client >/dev/null 2>&1
fi

echo "========================================"
echo " Scenario 04: X11 Forwarding + MaxAuthTries"
echo "========================================"

###############################################################################
# PoC Test: Check X11Forwarding
###############################################################################
echo ""
echo "[PoC Test] Checking X11Forwarding configuration..."

X11FWD=$(sshd -T 2>/dev/null | grep -i "^x11forwarding" | awk '{print $2}')
echo "  X11Forwarding is set to: ${X11FWD:-unknown}"

if echo "$X11FWD" | grep -qi "^yes$"; then
    echo "  [FAIL] X11Forwarding is still enabled"
    exit $FAIL
fi

echo "  [PASS] X11Forwarding is disabled"

###############################################################################
# PoC Test: Check MaxAuthTries
###############################################################################
echo ""
echo "[PoC Test] Checking MaxAuthTries configuration..."

MAX_AUTH=$(sshd -T 2>/dev/null | grep -i "^maxauthtries" | awk '{print $2}')
echo "  MaxAuthTries is set to: ${MAX_AUTH:-unknown}"

if [ -z "$MAX_AUTH" ]; then
    echo "  [FAIL] Could not determine MaxAuthTries"
    exit $FAIL
fi

if [ "$MAX_AUTH" -gt 6 ]; then
    echo "  [FAIL] MaxAuthTries is $MAX_AUTH (should be 6 or less)"
    exit $FAIL
fi

echo "  [PASS] MaxAuthTries is $MAX_AUTH (acceptable: <= 6)"

###############################################################################
# PoC Behavioral Test: X11 forwarding should be rejected at connection time
###############################################################################
echo ""
echo "[PoC Test] Attempting SSH connection with X11 forwarding request..."

# Ensure sshd is running for behavioral test
if ! pgrep -x sshd >/dev/null 2>&1; then
    /usr/sbin/sshd 2>/dev/null
    sleep 1
fi

X11_RESULT=$(sshpass -p 'TestPass123!' ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=5 -X -v -p 22 testuser@127.0.0.1 "echo x11_test_done" 2>&1 || true)

if echo "$X11_RESULT" | grep -qi "X11 forwarding request failed\|Requesting X11 forwarding.*rejected"; then
    echo "  [PASS] X11 forwarding request was denied by server"
elif echo "$X11_RESULT" | grep -q "x11_test_done"; then
    # Connection worked but check if X11 was actually granted
    if echo "$X11_RESULT" | grep -qi "Requesting X11 forwarding"; then
        if ! echo "$X11_RESULT" | grep -qi "X11 forwarding.*success\|DISPLAY"; then
            echo "  [PASS] SSH connected but X11 forwarding was not granted"
        else
            echo "  [FAIL] X11 forwarding appears to have been granted"
            exit $FAIL
        fi
    else
        echo "  [PASS] SSH connected without X11 forwarding"
    fi
else
    echo "  [PASS] SSH did not grant X11 forwarding (connection output indicates denial)"
fi

###############################################################################
# Regression Test: SSH service must still be running
###############################################################################
echo ""
echo "[Regression Test] Checking SSH service is running..."

if ! pgrep -x sshd >/dev/null 2>&1; then
    echo "  [FAIL] sshd process is not running"
    exit $FAIL
fi
echo "  [PASS] sshd process is running"

###############################################################################
# Regression Test: SSH connection must still work
###############################################################################
echo ""
echo "[Regression Test] Attempting SSH login as testuser..."

RESULT=$(sshpass -p 'TestPass123!' ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=5 \
    -p 22 testuser@127.0.0.1 "echo user_access_granted" 2>/dev/null || true)

if [ "$RESULT" != "user_access_granted" ]; then
    echo "  [FAIL] SSH login failed - service is broken"
    exit $FAIL
fi
echo "  [PASS] SSH login works correctly"

###############################################################################
# All tests passed
###############################################################################
echo ""
echo "========================================"
echo " RESULT: REMEDIATION SUCCESSFUL"
echo "========================================"
exit $PASS
