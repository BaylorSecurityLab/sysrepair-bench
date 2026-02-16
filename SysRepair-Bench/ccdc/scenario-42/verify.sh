#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Scenario 42: World-Writable /tmp Without Sticky Bit
# Verify that the sticky bit has been restored on /tmp
# =============================================================================

FAIL=0

# --- PoC Test: Check if /tmp is missing the sticky bit ---
echo "[PoC] Checking if /tmp has the sticky bit set..."

TMP_PERMS=$(stat -c '%a' /tmp)
TMP_MODE=$(stat -c '%A' /tmp)

# Check for sticky bit: permissions should start with 1 (e.g., 1777)
# Or the symbolic mode should end with 't' or 'T'
if echo "$TMP_MODE" | grep -q 't$\|T$'; then
    echo "[PoC] PASS: /tmp has the sticky bit set (mode: $TMP_PERMS, symbolic: $TMP_MODE)."
else
    echo "[PoC] FAIL: /tmp is missing the sticky bit (mode: $TMP_PERMS, symbolic: $TMP_MODE)."
    echo "[PoC] RESULT: Vulnerability still exploitable -- any user can delete others' files in /tmp."
    exit 1
fi

# --- Regression Test: Ensure /tmp is still writable by users ---
echo ""
echo "[Regression] Checking that /tmp is still usable by regular users..."

# Test that alice can create a file in /tmp
ALICE_RESULT=$(su -s /bin/bash -c "touch /tmp/alice_testfile_$$ && echo ok" alice 2>&1) || true
if [ "$ALICE_RESULT" = "ok" ]; then
    echo "[Regression] PASS: User alice can create files in /tmp."
else
    echo "[Regression] FAIL: User alice cannot create files in /tmp. Got: $ALICE_RESULT"
    FAIL=1
fi

# Test that bob can create a file in /tmp
BOB_RESULT=$(su -s /bin/bash -c "touch /tmp/bob_testfile_$$ && echo ok" bob 2>&1) || true
if [ "$BOB_RESULT" = "ok" ]; then
    echo "[Regression] PASS: User bob can create files in /tmp."
else
    echo "[Regression] FAIL: User bob cannot create files in /tmp. Got: $BOB_RESULT"
    FAIL=1
fi

# Clean up test files
rm -f /tmp/alice_testfile_$$ /tmp/bob_testfile_$$ 2>/dev/null || true

if [ "$FAIL" -eq 1 ]; then
    echo ""
    echo "[RESULT] FAIL: Regression test failed -- /tmp not usable."
    exit 1
fi

echo ""
echo "[RESULT] SUCCESS: Sticky bit set on /tmp and directory remains usable."
exit 0
