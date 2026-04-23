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

# --- PoC Behavioral Test: live crypto probe against root's shadow hash ---
# Extract root's shadow field and run the baseline seed-password ("root123")
# through the same crypt scheme the hash uses. If it verifies, the account
# is *live-exploitable*, regardless of what passwd -S thinks.
# Baseline: hash is real sha-crypt of "root123" -> match -> [PoC] FAILS.
# Remediated: hash is "!" / "*" / "!<real>" -> crypt mismatch -> [PoC] PASSES.
echo ""
echo "[PoC] Live crypto-probe against root's shadow hash..."
SHADOW_HASH=$(awk -F: '$1 == "root" {print $2}' /etc/shadow 2>/dev/null || true)
if [ -z "$SHADOW_HASH" ]; then
    echo "[PoC] PASS: root has no shadow hash field (locked or absent)."
elif [[ "$SHADOW_HASH" == "!"* ]] || [[ "$SHADOW_HASH" == "*" ]] || [[ "$SHADOW_HASH" == "!" ]]; then
    echo "[PoC] PASS: root shadow field is a lock marker ('$SHADOW_HASH')."
else
    # Live probe: see if the known-bad baseline password still matches.
    # Use openssl passwd with the $id$salt$ prefix of the real hash.
    SALT_PART=$(echo "$SHADOW_HASH" | awk -F'$' 'NF>=3 {print "$"$2"$"$3"$"}')
    if [ -n "$SALT_PART" ] && command -v openssl >/dev/null 2>&1; then
        REHASH=$(openssl passwd -salt "$SALT_PART" "root123" 2>/dev/null || true)
        # openssl -salt with full $id$salt$ form yields the full hash; compare.
        # Fallback: use python3 crypt if openssl is uncooperative.
        if [ "$REHASH" = "$SHADOW_HASH" ]; then
            echo "[PoC] FAIL: root's live shadow hash verifies against known seed password 'root123'."
            echo "RESULT: Vulnerability still exploitable -- weak root password still works."
            exit 1
        fi
    fi
    if command -v python3 >/dev/null 2>&1; then
        PYRES=$(python3 -c "import crypt,sys; print('1' if crypt.crypt('root123','$SHADOW_HASH')=='$SHADOW_HASH' else '0')" 2>/dev/null || echo "x")
        if [ "$PYRES" = "1" ]; then
            echo "[PoC] FAIL: python crypt confirms root's hash matches 'root123'."
            echo "RESULT: Vulnerability still exploitable -- weak root password still works."
            exit 1
        fi
    fi
    echo "[PoC] PASS: root's active hash does not match the known-weak seed password."
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
