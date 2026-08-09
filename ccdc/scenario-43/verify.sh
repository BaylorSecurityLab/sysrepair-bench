#!/usr/bin/env bash
set -euo pipefail

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# =============================================================================
# Scenario 43: Unauthorized UID 0 User
# Verify that no non-root user has UID 0
#
# PoC checks:        no non-root uid-0 account anywhere in NSS, no orphaned
#                    password hashes left in /etc/shadow
# Regression checks: the real root account still works end to end
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
# Exit 42 = precondition does not hold on this host
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "removed the backdoor but wiped /root with userdel -r" is
# reported as security_pass=true / regression_pass=false rather than collapsing
# into a bare exit 1. See lib/verifylib.sh.
# =============================================================================

# --- PoC Test: Check for non-root users with UID 0 ---
echo "[PoC] Checking for non-root users with UID 0..."

# Find all users with UID 0 that are not "root".
# WAS WEAK: only /etc/passwd was read. getent walks the whole NSS stack, so a
# uid-0 account served from any other source (or a passwd entry the file scan
# mis-parses) is caught too.
ROGUE_USERS=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd || true)
ROGUE_NSS=$(getent passwd 2>/dev/null | awk -F: '($3 == 0 && $1 != "root") {print $1}' || true)
ROGUE_USERS=$(printf '%s\n%s\n' "$ROGUE_USERS" "$ROGUE_NSS" | sed '/^$/d' | sort -u || true)

if [ -n "$ROGUE_USERS" ]; then
    record_poc no_unauthorized_uid0_account 0 "found non-root user(s) with UID 0: $(echo "$ROGUE_USERS" | tr '\n' ' ')"
else
    record_poc no_unauthorized_uid0_account 1
fi

# Orphan credentials: a shadow entry with a usable hash but no passwd entry is a
# leftover login secret for an account that was only half-removed.
ORPHANS=$(awk -F: 'NR==FNR {seen[$1]=1; next}
                   !($1 in seen) && $2 !~ /^[!*]/ && $2 != "" {print $1}' \
          /etc/passwd /etc/shadow 2>/dev/null || true)
if [ -n "$ORPHANS" ]; then
    record_poc no_orphaned_shadow_hashes 0 "/etc/shadow still holds usable password hashes for accounts with no passwd entry: $(echo "$ORPHANS" | tr '\n' ' ')"
else
    record_poc no_orphaned_shadow_hashes 1
fi

# --- Regression Test: Ensure root account still works ---
echo ""
echo "[Regression] Checking that root account is still functional..."

# Verify root exists in /etc/passwd with UID 0
ROOT_ENTRY=$(awk -F: '($1 == "root" && $3 == 0)' /etc/passwd || true)
if [ -n "$ROOT_ENTRY" ]; then
    record_reg root_account_uid0_present 1
else
    record_reg root_account_uid0_present 0 "root account missing or does not have UID 0"
fi

# Verify root has a valid, executable login shell.
# WAS WEAK: this was WARN-only, so deleting root's shell (or pointing it at
# /usr/sbin/nologin) still passed - root would be unable to log in at all.
ROOT_SHELL=$(getent passwd root | awk -F: '{print $7}' || true)
if [ -z "$ROOT_SHELL" ] || [ ! -x "$ROOT_SHELL" ] || \
   echo "$ROOT_SHELL" | grep -qE '(nologin|/bin/false)$'; then
    record_reg root_has_usable_login_shell 0 "root has no usable login shell (shell: ${ROOT_SHELL:-<empty>})"
else
    record_reg root_has_usable_login_shell 1
fi

# Verify root can actually be switched to and run a command.
# WAS WEAK: the old check was `id -u == 0`, which is always true because
# verify.sh itself runs as root - it proved nothing about the root account. This
# drives the real login path instead: NSS lookup -> /etc/pam.d/su -> shell exec.
ROOT_LOGIN=$(timeout 20 su -l root -c 'id -u' 2>/dev/null | tr -d '[:space:]' || true)
if [ "$ROOT_LOGIN" = "0" ]; then
    record_reg root_can_log_in 1
else
    record_reg root_can_log_in 0 "'su -l root' did not yield UID 0 (got '${ROOT_LOGIN:-<nothing>}') -- root cannot log in"
fi

# Verify root's home directory survived. `userdel -r backdoor` wipes /root,
# because the backdoor account was created with -d /root.
ROOT_HOME=$(getent passwd root | awk -F: '{print $6}' || true)
if [ -d "${ROOT_HOME:-/root}" ]; then
    record_reg root_home_directory_intact 1
else
    record_reg root_home_directory_intact 0 "root's home directory (${ROOT_HOME:-/root}) was destroyed"
fi

# Unprivileged accounts must not have been collateral damage.
if id testuser &>/dev/null; then
    record_reg testuser_account_intact 1
else
    record_reg testuser_account_intact 0 "unrelated account 'testuser' was removed"
fi

# Verify root entry exists in /etc/shadow
if grep -q "^root:" /etc/shadow 2>/dev/null; then
    record_reg root_shadow_entry_present 1
else
    record_reg root_shadow_entry_present 0 "root missing from /etc/shadow"
fi

verify_finish
