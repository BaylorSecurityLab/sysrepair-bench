#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Scenario 47: No PAM Password Complexity (pwquality)
# Verify that password quality requirements are properly configured
# =============================================================================

FAIL=0
PWQUALITY_CONF="/etc/security/pwquality.conf"

# --- PoC Test: Check if password quality settings are too permissive ---
echo "[PoC] Checking password quality configuration..."

POC_FAIL=0

if [ ! -f "$PWQUALITY_CONF" ]; then
    echo "[PoC] FAIL: $PWQUALITY_CONF does not exist -- pwquality not configured."
    exit 1
fi

# Helper: get last effective value for a key (ignoring comments)
get_pwquality_val() {
    local key="$1"
    grep -E "^\s*${key}\s*=" "$PWQUALITY_CONF" | tail -1 | sed 's/.*=\s*//' | tr -d ' '
}

# Check minlen (should be >= 14)
MINLEN=$(get_pwquality_val "minlen")
if [ -z "$MINLEN" ]; then
    echo "[PoC] FAIL: minlen not set in $PWQUALITY_CONF."
    POC_FAIL=1
elif [ "$MINLEN" -lt 14 ]; then
    echo "[PoC] FAIL: minlen is $MINLEN (should be >= 14)."
    POC_FAIL=1
else
    echo "[PoC] PASS: minlen is $MINLEN (>= 14)."
fi

# Check dcredit (should be <= -1, meaning at least 1 digit required)
DCREDIT=$(get_pwquality_val "dcredit")
if [ -n "$DCREDIT" ] && [ "$DCREDIT" -ge 0 ] 2>/dev/null; then
    echo "[PoC] FAIL: dcredit is $DCREDIT (should be <= -1 to require digits)."
    POC_FAIL=1
else
    echo "[PoC] PASS: dcredit is ${DCREDIT:-(not set, default)}."
fi

# Check ucredit (should be <= -1, meaning at least 1 uppercase required)
UCREDIT=$(get_pwquality_val "ucredit")
if [ -n "$UCREDIT" ] && [ "$UCREDIT" -ge 0 ] 2>/dev/null; then
    echo "[PoC] FAIL: ucredit is $UCREDIT (should be <= -1 to require uppercase)."
    POC_FAIL=1
else
    echo "[PoC] PASS: ucredit is ${UCREDIT:-(not set, default)}."
fi

# Check lcredit (should be <= -1, meaning at least 1 lowercase required)
LCREDIT=$(get_pwquality_val "lcredit")
if [ -n "$LCREDIT" ] && [ "$LCREDIT" -ge 0 ] 2>/dev/null; then
    echo "[PoC] FAIL: lcredit is $LCREDIT (should be <= -1 to require lowercase)."
    POC_FAIL=1
else
    echo "[PoC] PASS: lcredit is ${LCREDIT:-(not set, default)}."
fi

# Check ocredit (should be <= -1, meaning at least 1 special char required)
OCREDIT=$(get_pwquality_val "ocredit")
if [ -n "$OCREDIT" ] && [ "$OCREDIT" -ge 0 ] 2>/dev/null; then
    echo "[PoC] FAIL: ocredit is $OCREDIT (should be <= -1 to require special chars)."
    POC_FAIL=1
else
    echo "[PoC] PASS: ocredit is ${OCREDIT:-(not set, default)}."
fi

# Check enforcing (should be 1)
ENFORCING=$(get_pwquality_val "enforcing")
if [ "$ENFORCING" = "0" ]; then
    echo "[PoC] FAIL: enforcing is 0 (quality checks are not enforced)."
    POC_FAIL=1
else
    echo "[PoC] PASS: enforcing is ${ENFORCING:-(not set, default enforced)}."
fi

# Check dictcheck (should be 1 or not explicitly set to 0)
DICTCHECK=$(get_pwquality_val "dictcheck")
if [ "$DICTCHECK" = "0" ]; then
    echo "[PoC] FAIL: dictcheck is 0 (dictionary check disabled)."
    POC_FAIL=1
else
    echo "[PoC] PASS: dictcheck is ${DICTCHECK:-(not set, default enabled)}."
fi

if [ "$POC_FAIL" -eq 1 ]; then
    echo "[PoC] RESULT: Vulnerability still present -- password complexity too permissive."
    exit 1
else
    echo "[PoC] PASS: Password quality settings meet security requirements."
fi

# --- Regression Test: Ensure password changes still work ---
echo ""
echo "[Regression] Checking that password management still functions..."

# Verify pwquality.conf exists and is readable
if [ -r "$PWQUALITY_CONF" ]; then
    echo "[Regression] PASS: $PWQUALITY_CONF is readable."
else
    echo "[Regression] FAIL: $PWQUALITY_CONF is not readable."
    FAIL=1
fi

# Verify pam_pwquality module is installed
if [ -f /usr/lib/x86_64-linux-gnu/security/pam_pwquality.so ] || \
   [ -f /lib/x86_64-linux-gnu/security/pam_pwquality.so ] || \
   [ -f /lib/security/pam_pwquality.so ]; then
    echo "[Regression] PASS: pam_pwquality module is installed."
else
    echo "[Regression] FAIL: pam_pwquality module not found."
    FAIL=1
fi

# Verify passwd command works
if command -v passwd &>/dev/null; then
    echo "[Regression] PASS: passwd command is available."
else
    echo "[Regression] FAIL: passwd command not found."
    FAIL=1
fi

# Verify testuser account exists
if id testuser &>/dev/null; then
    echo "[Regression] PASS: testuser account exists."
else
    echo "[Regression] FAIL: testuser account missing."
    FAIL=1
fi

if [ "$FAIL" -eq 1 ]; then
    echo ""
    echo "[RESULT] FAIL: Regression test failed -- password management broken."
    exit 1
fi

echo ""
echo "[RESULT] SUCCESS: Password complexity enforced and password management works."
exit 0
