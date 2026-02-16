#!/usr/bin/env bash
###############################################################################
# Scenario 03 - Verification Script
# SSH Weak Ciphers Configured (CWE-327)
#
# PoC Test:        Verify weak ciphers (3des-cbc, aes128-cbc) are not offered
# Regression Test: Verify SSH still works with strong ciphers
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
echo " Scenario 03: SSH Weak Ciphers"
echo "========================================"

# List of weak ciphers to check for
WEAK_CIPHERS="3des-cbc aes128-cbc aes192-cbc aes256-cbc arcfour arcfour128 arcfour256 blowfish-cbc cast128-cbc"

###############################################################################
# PoC Test: Check that no weak ciphers are configured
###############################################################################
echo ""
echo "[PoC Test] Checking for weak ciphers in sshd configuration..."

CONFIGURED_CIPHERS=$(sshd -T 2>/dev/null | grep -i "^ciphers" | awk '{print $2}')
echo "  Configured ciphers: ${CONFIGURED_CIPHERS:-default}"

FOUND_WEAK=0
for cipher in $WEAK_CIPHERS; do
    if echo "$CONFIGURED_CIPHERS" | grep -qi "$cipher"; then
        echo "  [FAIL] Weak cipher found: $cipher"
        FOUND_WEAK=1
    fi
done

if [ $FOUND_WEAK -eq 1 ]; then
    echo "  [FAIL] Weak ciphers are still configured"
    exit $FAIL
fi

echo "  [PASS] No weak ciphers found in configuration"

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
# Regression Test: SSH must work with strong ciphers
###############################################################################
echo ""
echo "[Regression Test] Testing SSH connection with strong cipher (aes256-ctr)..."

RESULT=$(sshpass -p 'TestPass123!' ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=5 -c aes256-ctr \
    -p 22 testuser@127.0.0.1 "echo cipher_test_passed" 2>/dev/null || true)

if [ "$RESULT" != "cipher_test_passed" ]; then
    echo "  [FAIL] SSH connection with strong cipher failed"
    exit $FAIL
fi
echo "  [PASS] SSH works with strong ciphers"

###############################################################################
# All tests passed
###############################################################################
echo ""
echo "========================================"
echo " RESULT: REMEDIATION SUCCESSFUL"
echo "========================================"
exit $PASS
