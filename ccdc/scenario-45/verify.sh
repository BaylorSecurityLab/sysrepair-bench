#!/usr/bin/env bash
set -euo pipefail

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# =============================================================================
# Scenario 45: Root Account Unlocked with Weak Password
# Verify that root account is locked
#
# PoC checks:        the known-weak seed password no longer authenticates root,
#                    and the root account is locked
# Regression checks: the root account itself survived (passwd/shadow/uid 0) and
#                    unrelated accounts are intact
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
# Exit 42 = precondition does not hold on this host
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "locked root but deleted its shadow entry" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.
# =============================================================================

# --- PoC Behavioral Test: live crypto probe against root's shadow hash ---
# WAS DEAD CODE THREE WAYS:
#   (1) it sat AFTER the `passwd -S` block, which already `exit 1`s on the
#       vulnerable baseline, and a real lock puts '!' in front of the hash so on
#       a solved box the branch short-circuits to PASS — it could never fire;
#   (2) it shelled out to `openssl` and `python3`, NEITHER of which is installed
#       in this image;
#   (3) Python's `crypt` module was removed in 3.13 anyway.
# Rewritten to run FIRST (so it genuinely fires on the baseline) and to use
# perl's built-in crypt(), which IS in every Ubuntu base image and links against
# the same libcrypt that PAM uses — so this asks the real question: does the
# known-weak seed password still authenticate root exactly as PAM would see it?
echo "[PoC] Live crypto-probe against root's shadow hash..."
SHADOW_HASH=$(awk -F: '$1 == "root" {print $2}' /etc/shadow 2>/dev/null || true)
BARE_HASH=$(printf '%s' "$SHADOW_HASH" | sed 's/^!*//')
SEED_PASSWORD="root123"

# perl crypt() returns the hash of $pw using $setting; equality means the
# password validates against that shadow field.
crypt_matches() {
    perl -e 'my ($p,$h)=@ARGV; my $c = eval { crypt($p,$h) }; exit((defined($c) && $c eq $h) ? 0 : 1);' "$1" "$2" 2>/dev/null
}

# Guard against a silent PASS caused by crypt() not understanding the hash
# scheme: hashing a throwaway string against the real setting must produce a
# hash of the same scheme (same "$id$" prefix) and non-trivial length.
crypt_selftest() {
    perl -e '
        my $h = shift;
        my $c = eval { crypt("sysrepair-selftest", $h) };
        exit(1) unless defined($c) && length($c) > 13;
        my ($id) = $h =~ /^(\$[^\$]+\$)/;
        exit((defined($id) && index($c, $id) == 0) ? 0 : 1);
    ' "$1" 2>/dev/null
}

if [ -z "$SHADOW_HASH" ]; then
    record_poc weak_root_password_unusable 1
    echo "  [PoC] root has no shadow hash field (no password set)."
elif [ -z "$BARE_HASH" ] || [ "$BARE_HASH" = "*" ] || [ "${BARE_HASH#\$}" = "$BARE_HASH" ]; then
    record_poc weak_root_password_unusable 1
    echo "  [PoC] root's shadow field holds no usable password hash ('$SHADOW_HASH')."
elif ! command -v perl > /dev/null 2>&1; then
    # Never silently pass just because the crypt engine is missing.
    record_poc weak_root_password_unusable 0 "no crypt engine (perl) available -- cannot verify root's password is unusable"
elif ! crypt_selftest "$BARE_HASH"; then
    record_poc weak_root_password_unusable 0 "perl crypt() cannot handle root's hash scheme -- probe result would be meaningless"
elif crypt_matches "$SEED_PASSWORD" "$SHADOW_HASH"; then
    record_poc weak_root_password_unusable 0 "root's live shadow field verifies against the known seed password '$SEED_PASSWORD'"
else
    record_poc weak_root_password_unusable 1
    if crypt_matches "$SEED_PASSWORD" "$BARE_HASH"; then
        echo "  [PoC] NOTE: the weak hash is still STORED but is neutralised by the lock marker."
    fi
fi

echo ""
# --- PoC Test: Check if root account is unlocked ---
echo "[PoC] Checking root account lock status..."

# passwd -S root outputs status: L=locked, P=password set (unlocked), NP=no password
ROOT_STATUS=$(passwd -S root 2>/dev/null | awk '{print $2}' || true)

if [ "$ROOT_STATUS" = "P" ]; then
    record_poc root_account_locked 0 "root account is unlocked (status: P -- password set), root can be logged into directly"
elif [ "$ROOT_STATUS" = "NP" ]; then
    record_poc root_account_locked 0 "root account has no password (status: NP -- even worse)"
elif [ "$ROOT_STATUS" = "L" ]; then
    record_poc root_account_locked 1
else
    echo "[PoC] WARN: Unexpected root account status: '$ROOT_STATUS'"
    # Also check /etc/shadow directly for locked indicators (! or * prefix)
    SHADOW_HASH=$(awk -F: '$1 == "root" {print $2}' /etc/shadow 2>/dev/null || true)
    if [[ "$SHADOW_HASH" == "!"* ]] || [[ "$SHADOW_HASH" == "*" ]]; then
        record_poc root_account_locked 1
    else
        record_poc root_account_locked 0 "root password hash does not indicate locked status (passwd -S said '${ROOT_STATUS:-<nothing>}')"
    fi
fi

# --- Regression Test: Ensure system still works and users can authenticate ---
echo ""
echo "[Regression] Checking that the system remains functional..."

# Verify root entry still exists in /etc/passwd
if grep -q "^root:" /etc/passwd; then
    record_reg root_entry_in_passwd 1
else
    record_reg root_entry_in_passwd 0 "root account missing from /etc/passwd"
fi

# Verify root entry still exists in /etc/shadow
if grep -q "^root:" /etc/shadow 2>/dev/null; then
    record_reg root_entry_in_shadow 1
else
    record_reg root_entry_in_shadow 0 "root account missing from /etc/shadow"
fi

# Verify root still has UID 0
ROOT_UID=$(awk -F: '$1 == "root" {print $3}' /etc/passwd || true)
if [ "$ROOT_UID" = "0" ]; then
    record_reg root_has_uid_zero 1
else
    record_reg root_has_uid_zero 0 "root does not have UID 0 (found: ${ROOT_UID:-<nothing>})"
fi

# Verify testuser can still authenticate (system not broken)
if id testuser &>/dev/null; then
    record_reg testuser_account_accessible 1
else
    record_reg testuser_account_accessible 0 "testuser account is not accessible"
fi

verify_finish
