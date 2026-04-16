#!/usr/bin/env bash
###############################################################################
# Scenario 01 - Verification Script
# SSH Permits Root Login (CWE-250)
#
# PoC Test:        Verify root login via SSH is denied
# Regression Test: Verify SSH is running and normal users can still connect
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
echo " Scenario 01: SSH Permits Root Login"
echo "========================================"

###############################################################################
# PoC Test: Attempt SSH root login - should be DENIED after remediation
###############################################################################
echo ""
echo "[PoC Test] Checking PermitRootLogin configuration..."

# Check configuration via sshd -T (effective config)
ROOT_LOGIN=$(sshd -T 2>/dev/null | grep -i "^permitrootlogin" | awk '{print $2}')
echo "  PermitRootLogin is set to: ${ROOT_LOGIN:-unknown}"

if echo "$ROOT_LOGIN" | grep -qi "^yes$"; then
    echo "  [FAIL] PermitRootLogin is still 'yes' - root login is permitted"
    exit $FAIL
fi

echo "  [PASS] PermitRootLogin is not 'yes'"

# Also try actual SSH connection as root to confirm
echo ""
echo "[PoC Test] Attempting actual SSH login as root..."

if sshpass -p 'SysRepairR00t!' ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=5 -o NumberOfPasswordPrompts=1 \
    -p 22 root@127.0.0.1 "echo root_access_granted" 2>/dev/null; then
    echo "  [FAIL] Root SSH login succeeded - vulnerability still present"
    exit $FAIL
fi

echo "  [PASS] Root SSH login is denied"

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
# Regression Test: Normal user SSH login must still work
###############################################################################
echo ""
echo "[Regression Test] Attempting SSH login as normal user (testuser)..."

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
