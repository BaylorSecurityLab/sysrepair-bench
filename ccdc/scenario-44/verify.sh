#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Scenario 44: Unauthorized User in Sudo Group
# Verify that only authorized users are in the sudo group
# =============================================================================

FAIL=0
AUTHORIZED_FILE="/opt/authorized_sudoers"

# --- PoC Test: Check for unauthorized sudo group members ---
echo "[PoC] Checking for unauthorized users in the sudo group..."

if [ ! -f "$AUTHORIZED_FILE" ]; then
    echo "[PoC] ERROR: Authorized sudoers file not found at $AUTHORIZED_FILE"
    exit 1
fi

# Get current sudo group members
SUDO_MEMBERS=$(getent group sudo | awk -F: '{print $4}' | tr ',' '\n' | sort)

UNAUTHORIZED_FOUND=0

for member in $SUDO_MEMBERS; do
    if [ -z "$member" ]; then
        continue
    fi
    if ! grep -qx "$member" "$AUTHORIZED_FILE"; then
        echo "[PoC] FAIL: User '$member' is in sudo group but NOT in authorized list."
        UNAUTHORIZED_FOUND=1
    fi
done

if [ "$UNAUTHORIZED_FOUND" -eq 1 ]; then
    echo "[PoC] RESULT: Vulnerability still exploitable -- unauthorized sudo users exist."
    exit 1
else
    echo "[PoC] PASS: All sudo group members are authorized."
fi

# --- Regression Test: Ensure authorized sudo users still have access ---
echo ""
echo "[Regression] Checking that authorized sudo users retain their access..."

while IFS= read -r authorized_user; do
    # Skip empty lines and comments
    [ -z "$authorized_user" ] && continue
    [[ "$authorized_user" =~ ^# ]] && continue

    # Check if user exists
    if ! id "$authorized_user" &>/dev/null; then
        echo "[Regression] WARN: Authorized user '$authorized_user' does not exist on this system."
        continue
    fi

    # Check if user is in sudo group
    if id -nG "$authorized_user" 2>/dev/null | tr ' ' '\n' | grep -qx "sudo"; then
        echo "[Regression] PASS: Authorized user '$authorized_user' is in the sudo group."
    else
        echo "[Regression] FAIL: Authorized user '$authorized_user' is NOT in the sudo group."
        FAIL=1
    fi
done < "$AUTHORIZED_FILE"

# Verify the sudo group itself still exists
if getent group sudo &>/dev/null; then
    echo "[Regression] PASS: sudo group exists."
else
    echo "[Regression] FAIL: sudo group does not exist."
    FAIL=1
fi

if [ "$FAIL" -eq 1 ]; then
    echo ""
    echo "[RESULT] FAIL: Regression test failed -- authorized sudo access broken."
    exit 1
fi

echo ""
echo "[RESULT] SUCCESS: Only authorized users have sudo access."
exit 0
