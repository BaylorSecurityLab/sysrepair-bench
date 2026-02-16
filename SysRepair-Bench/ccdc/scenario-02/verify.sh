#!/usr/bin/env bash
###############################################################################
# Scenario 02 - Verification Script
# SSH Allows Empty Passwords (CWE-258)
#
# PoC Test:        Verify empty-password SSH login is denied
# Regression Test: Verify SSH works with real passwords
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
echo " Scenario 02: SSH Allows Empty Passwords"
echo "========================================"

###############################################################################
# PoC Test: Check configuration for PermitEmptyPasswords
###############################################################################
echo ""
echo "[PoC Test] Checking PermitEmptyPasswords configuration..."

EMPTY_PW=$(sshd -T 2>/dev/null | grep -i "^permitemptypasswords" | awk '{print $2}')
echo "  PermitEmptyPasswords is set to: ${EMPTY_PW:-unknown}"

if echo "$EMPTY_PW" | grep -qi "^yes$"; then
    echo "  [FAIL] PermitEmptyPasswords is still 'yes'"
    exit $FAIL
fi

echo "  [PASS] PermitEmptyPasswords is not 'yes'"

###############################################################################
# PoC Test: Attempt SSH login with empty password
###############################################################################
echo ""
echo "[PoC Test] Attempting SSH login with empty password (emptyuser)..."

# Try to SSH with an empty password
RESULT=$(sshpass -p '' ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=5 -o NumberOfPasswordPrompts=1 \
    -p 22 emptyuser@127.0.0.1 "echo empty_access_granted" 2>/dev/null || true)

if [ "$RESULT" = "empty_access_granted" ]; then
    echo "  [FAIL] Empty password SSH login succeeded - vulnerability still present"
    exit $FAIL
fi

echo "  [PASS] Empty password SSH login is denied"

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
# Regression Test: Normal user with real password must still work
###############################################################################
echo ""
echo "[Regression Test] Attempting SSH login with real password (testuser)..."

RESULT=$(sshpass -p 'TestPass123!' ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=5 \
    -p 22 testuser@127.0.0.1 "echo user_access_granted" 2>/dev/null || true)

if [ "$RESULT" != "user_access_granted" ]; then
    echo "  [FAIL] Normal user SSH login failed - SSH service is broken"
    exit $FAIL
fi
echo "  [PASS] Normal user SSH login works correctly"

###############################################################################
# All tests passed
###############################################################################
echo ""
echo "========================================"
echo " RESULT: REMEDIATION SUCCESSFUL"
echo "========================================"
exit $PASS
