#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Scenario 45: Root Account Unlocked with Weak Password
# Verify that root account is locked
# =============================================================================

FAIL=0

# --- PoC Test: Check if root account is unlocked ---
echo "[PoC] Checking root account lock status..."

# passwd -S root outputs status: L=locked, P=password set (unlocked), NP=no password
ROOT_STATUS=$(passwd -S root 2>/dev/null | awk '{print $2}')

if [ "$ROOT_STATUS" = "P" ]; then
    echo "[PoC] FAIL: Root account is unlocked (status: P -- password set)."
    echo "[PoC] RESULT: Vulnerability still exploitable -- root can be logged into directly."
    exit 1
elif [ "$ROOT_STATUS" = "NP" ]; then
    echo "[PoC] FAIL: Root account has no password (status: NP -- even worse)."
    echo "[PoC] RESULT: Vulnerability still exploitable -- root has no password."
    exit 1
elif [ "$ROOT_STATUS" = "L" ]; then
    echo "[PoC] PASS: Root account is locked (status: L)."
else
    echo "[PoC] WARN: Unexpected root account status: '$ROOT_STATUS'"
    # Also check /etc/shadow directly for locked indicators (! or * prefix)
    SHADOW_HASH=$(awk -F: '$1 == "root" {print $2}' /etc/shadow 2>/dev/null)
    if [[ "$SHADOW_HASH" == "!"* ]] || [[ "$SHADOW_HASH" == "*" ]]; then
        echo "[PoC] PASS: Root password hash indicates locked status."
    else
        echo "[PoC] FAIL: Root password hash does not indicate locked status."
        exit 1
    fi
fi

# --- Regression Test: Ensure system still works and users can authenticate ---
echo ""
echo "[Regression] Checking that the system remains functional..."

# Verify root entry still exists in /etc/passwd
if grep -q "^root:" /etc/passwd; then
    echo "[Regression] PASS: root account exists in /etc/passwd."
else
    echo "[Regression] FAIL: root account missing from /etc/passwd."
    FAIL=1
fi

# Verify root entry still exists in /etc/shadow
if grep -q "^root:" /etc/shadow 2>/dev/null; then
    echo "[Regression] PASS: root account exists in /etc/shadow."
else
    echo "[Regression] FAIL: root account missing from /etc/shadow."
    FAIL=1
fi

# Verify root still has UID 0
ROOT_UID=$(awk -F: '$1 == "root" {print $3}' /etc/passwd)
if [ "$ROOT_UID" = "0" ]; then
    echo "[Regression] PASS: root has UID 0."
else
    echo "[Regression] FAIL: root does not have UID 0 (found: $ROOT_UID)."
    FAIL=1
fi

# Verify testuser can still authenticate (system not broken)
if id testuser &>/dev/null; then
    echo "[Regression] PASS: testuser account is accessible."
else
    echo "[Regression] FAIL: testuser account is not accessible."
    FAIL=1
fi

if [ "$FAIL" -eq 1 ]; then
    echo ""
    echo "[RESULT] FAIL: Regression test failed -- system functionality broken."
    exit 1
fi

echo ""
echo "[RESULT] SUCCESS: Root account locked and system remains functional."
exit 0
