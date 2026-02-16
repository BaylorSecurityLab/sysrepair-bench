#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Scenario 43: Unauthorized UID 0 User
# Verify that no non-root user has UID 0
# =============================================================================

FAIL=0

# --- PoC Test: Check for non-root users with UID 0 ---
echo "[PoC] Checking for non-root users with UID 0..."

# Find all users with UID 0 that are not "root"
ROGUE_USERS=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd)

if [ -n "$ROGUE_USERS" ]; then
    echo "[PoC] FAIL: Found non-root user(s) with UID 0: $ROGUE_USERS"
    echo "[PoC] RESULT: Vulnerability still exploitable -- unauthorized UID 0 accounts exist."
    exit 1
else
    echo "[PoC] PASS: No non-root users with UID 0 found."
fi

# --- Regression Test: Ensure root account still works ---
echo ""
echo "[Regression] Checking that root account is still functional..."

# Verify root exists in /etc/passwd with UID 0
ROOT_ENTRY=$(awk -F: '($1 == "root" && $3 == 0)' /etc/passwd)
if [ -n "$ROOT_ENTRY" ]; then
    echo "[Regression] PASS: root account exists with UID 0."
else
    echo "[Regression] FAIL: root account missing or does not have UID 0."
    FAIL=1
fi

# Verify root has a valid shell
ROOT_SHELL=$(awk -F: '$1 == "root" {print $7}' /etc/passwd)
if [ "$ROOT_SHELL" = "/bin/bash" ] || [ "$ROOT_SHELL" = "/bin/sh" ]; then
    echo "[Regression] PASS: root has valid shell: $ROOT_SHELL"
else
    echo "[Regression] WARN: root shell is $ROOT_SHELL (may be intentional)."
fi

# Verify root can execute commands
ROOT_TEST=$(id -u 2>&1)
if [ "$ROOT_TEST" = "0" ]; then
    echo "[Regression] PASS: Current session can run as root (UID 0)."
else
    echo "[Regression] INFO: Running as UID $ROOT_TEST (verify.sh may not be run as root)."
fi

# Verify root entry exists in /etc/shadow
if grep -q "^root:" /etc/shadow 2>/dev/null; then
    echo "[Regression] PASS: root has entry in /etc/shadow."
else
    echo "[Regression] FAIL: root missing from /etc/shadow."
    FAIL=1
fi

if [ "$FAIL" -eq 1 ]; then
    echo ""
    echo "[RESULT] FAIL: Regression test failed -- root account is broken."
    exit 1
fi

echo ""
echo "[RESULT] SUCCESS: No unauthorized UID 0 users and root account is intact."
exit 0
