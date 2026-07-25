#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Scenario 43: Unauthorized UID 0 User
# Verify that no non-root user has UID 0
# =============================================================================

FAIL=0

# --- PoC Test: Check for non-root users with UID 0 ---
echo "[PoC] Checking for non-root users with UID 0..."

# Find all users with UID 0 that are not "root".
# WAS WEAK: only /etc/passwd was read. getent walks the whole NSS stack, so a
# uid-0 account served from any other source (or a passwd entry the file scan
# mis-parses) is caught too.
ROGUE_USERS=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd)
ROGUE_NSS=$(getent passwd 2>/dev/null | awk -F: '($3 == 0 && $1 != "root") {print $1}')
ROGUE_USERS=$(printf '%s\n%s\n' "$ROGUE_USERS" "$ROGUE_NSS" | sed '/^$/d' | sort -u)

if [ -n "$ROGUE_USERS" ]; then
    echo "[PoC] FAIL: Found non-root user(s) with UID 0: $ROGUE_USERS"
    echo "[PoC] RESULT: Vulnerability still exploitable -- unauthorized UID 0 accounts exist."
    exit 1
else
    echo "[PoC] PASS: No non-root users with UID 0 found."
fi

# Orphan credentials: a shadow entry with a usable hash but no passwd entry is a
# leftover login secret for an account that was only half-removed.
ORPHANS=$(awk -F: 'NR==FNR {seen[$1]=1; next}
                   !($1 in seen) && $2 !~ /^[!*]/ && $2 != "" {print $1}' \
          /etc/passwd /etc/shadow 2>/dev/null)
if [ -n "$ORPHANS" ]; then
    echo "[PoC] FAIL: /etc/shadow still holds usable password hashes for accounts with no passwd entry: $(echo "$ORPHANS" | tr '\n' ' ')"
    echo "[PoC] RESULT: Vulnerability still exploitable -- orphaned credentials remain."
    exit 1
fi
echo "[PoC] PASS: No orphaned password hashes remain in /etc/shadow."

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

# Verify root has a valid, executable login shell.
# WAS WEAK: this was WARN-only, so deleting root's shell (or pointing it at
# /usr/sbin/nologin) still passed - root would be unable to log in at all.
ROOT_SHELL=$(getent passwd root | awk -F: '{print $7}')
if [ -z "$ROOT_SHELL" ] || [ ! -x "$ROOT_SHELL" ] || \
   echo "$ROOT_SHELL" | grep -qE '(nologin|/bin/false)$'; then
    echo "[Regression] FAIL: root has no usable login shell (shell: ${ROOT_SHELL:-<empty>})."
    FAIL=1
else
    echo "[Regression] PASS: root has a usable login shell: $ROOT_SHELL"
fi

# Verify root can actually be switched to and run a command.
# WAS WEAK: the old check was `id -u == 0`, which is always true because
# verify.sh itself runs as root - it proved nothing about the root account. This
# drives the real login path instead: NSS lookup -> /etc/pam.d/su -> shell exec.
ROOT_LOGIN=$(timeout 20 su -l root -c 'id -u' 2>/dev/null | tr -d '[:space:]')
if [ "$ROOT_LOGIN" = "0" ]; then
    echo "[Regression] PASS: 'su -l root' completes and reports UID 0 (PAM + shell + home intact)."
else
    echo "[Regression] FAIL: 'su -l root' did not yield UID 0 (got '${ROOT_LOGIN:-<nothing>}') -- root cannot log in."
    FAIL=1
fi

# Verify root's home directory survived. `userdel -r backdoor` wipes /root,
# because the backdoor account was created with -d /root.
ROOT_HOME=$(getent passwd root | awk -F: '{print $6}')
if [ -d "${ROOT_HOME:-/root}" ]; then
    echo "[Regression] PASS: root's home directory (${ROOT_HOME:-/root}) still exists."
else
    echo "[Regression] FAIL: root's home directory (${ROOT_HOME:-/root}) was destroyed."
    FAIL=1
fi

# Unprivileged accounts must not have been collateral damage.
if id testuser &>/dev/null; then
    echo "[Regression] PASS: unrelated account 'testuser' still exists."
else
    echo "[Regression] FAIL: unrelated account 'testuser' was removed."
    FAIL=1
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
