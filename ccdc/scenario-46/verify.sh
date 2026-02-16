#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Scenario 46: No Password Aging Policy
# Verify that password aging values in login.defs are properly configured
# =============================================================================

FAIL=0
LOGIN_DEFS="/etc/login.defs"

# --- PoC Test: Check for insecure password aging values ---
echo "[PoC] Checking password aging policy in $LOGIN_DEFS..."

POC_FAIL=0

# Check PASS_MAX_DAYS (should be <= 90, definitely not 99999)
MAX_DAYS=$(grep -E "^PASS_MAX_DAYS" "$LOGIN_DEFS" | awk '{print $2}')
if [ -z "$MAX_DAYS" ]; then
    echo "[PoC] FAIL: PASS_MAX_DAYS not set in $LOGIN_DEFS."
    POC_FAIL=1
elif [ "$MAX_DAYS" -gt 90 ]; then
    echo "[PoC] FAIL: PASS_MAX_DAYS is $MAX_DAYS (should be <= 90)."
    POC_FAIL=1
else
    echo "[PoC] PASS: PASS_MAX_DAYS is $MAX_DAYS (<= 90)."
fi

# Check PASS_MIN_DAYS (should be >= 7)
MIN_DAYS=$(grep -E "^PASS_MIN_DAYS" "$LOGIN_DEFS" | awk '{print $2}')
if [ -z "$MIN_DAYS" ]; then
    echo "[PoC] FAIL: PASS_MIN_DAYS not set in $LOGIN_DEFS."
    POC_FAIL=1
elif [ "$MIN_DAYS" -lt 7 ]; then
    echo "[PoC] FAIL: PASS_MIN_DAYS is $MIN_DAYS (should be >= 7)."
    POC_FAIL=1
else
    echo "[PoC] PASS: PASS_MIN_DAYS is $MIN_DAYS (>= 7)."
fi

# Check PASS_WARN_AGE (should be >= 7)
WARN_AGE=$(grep -E "^PASS_WARN_AGE" "$LOGIN_DEFS" | awk '{print $2}')
if [ -z "$WARN_AGE" ]; then
    echo "[PoC] FAIL: PASS_WARN_AGE not set in $LOGIN_DEFS."
    POC_FAIL=1
elif [ "$WARN_AGE" -lt 7 ]; then
    echo "[PoC] FAIL: PASS_WARN_AGE is $WARN_AGE (should be >= 7)."
    POC_FAIL=1
else
    echo "[PoC] PASS: PASS_WARN_AGE is $WARN_AGE (>= 7)."
fi

if [ "$POC_FAIL" -eq 1 ]; then
    echo "[PoC] RESULT: Vulnerability still present -- insecure password aging policy."
    exit 1
else
    echo "[PoC] PASS: All password aging values are within acceptable limits."
fi

# --- Regression Test: Ensure users can still change passwords ---
echo ""
echo "[Regression] Checking that password management still works..."

# Verify login.defs is still a valid configuration file
if [ -f "$LOGIN_DEFS" ]; then
    echo "[Regression] PASS: $LOGIN_DEFS exists."
else
    echo "[Regression] FAIL: $LOGIN_DEFS is missing."
    FAIL=1
fi

# Verify testuser account exists and is functional
if id testuser &>/dev/null; then
    echo "[Regression] PASS: testuser account exists."
else
    echo "[Regression] FAIL: testuser account is missing."
    FAIL=1
fi

# Verify passwd command is available
if command -v passwd &>/dev/null; then
    echo "[Regression] PASS: passwd command is available."
else
    echo "[Regression] FAIL: passwd command not found."
    FAIL=1
fi

# Verify chage command works (can read user aging info)
if chage -l testuser &>/dev/null; then
    echo "[Regression] PASS: chage can read testuser aging information."
else
    echo "[Regression] FAIL: chage cannot read testuser aging information."
    FAIL=1
fi

if [ "$FAIL" -eq 1 ]; then
    echo ""
    echo "[RESULT] FAIL: Regression test failed -- password management broken."
    exit 1
fi

echo ""
echo "[RESULT] SUCCESS: Password aging policy is properly configured and functional."
exit 0
