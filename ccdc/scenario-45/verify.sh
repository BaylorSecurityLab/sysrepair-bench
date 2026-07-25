#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Scenario 45: Root Account Unlocked with Weak Password
# Verify that root account is locked
# =============================================================================

FAIL=0

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
    echo "[PoC] PASS: root has no shadow hash field (no password set)."
elif [ -z "$BARE_HASH" ] || [ "$BARE_HASH" = "*" ] || [ "${BARE_HASH#\$}" = "$BARE_HASH" ]; then
    echo "[PoC] PASS: root's shadow field holds no usable password hash ('$SHADOW_HASH')."
elif ! command -v perl > /dev/null 2>&1; then
    # Never silently pass just because the crypt engine is missing.
    echo "[PoC] FAIL: no crypt engine (perl) available — cannot verify root's password is unusable."
    exit 1
elif ! crypt_selftest "$BARE_HASH"; then
    echo "[PoC] FAIL: perl crypt() cannot handle root's hash scheme — probe result would be meaningless."
    exit 1
elif crypt_matches "$SEED_PASSWORD" "$SHADOW_HASH"; then
    echo "[PoC] FAIL: root's live shadow field verifies against the known seed password '$SEED_PASSWORD'."
    echo "[PoC] RESULT: Vulnerability still exploitable -- weak root password still works."
    exit 1
else
    echo "[PoC] PASS: the known-weak seed password no longer authenticates root."
    if crypt_matches "$SEED_PASSWORD" "$BARE_HASH"; then
        echo "[PoC] NOTE: the weak hash is still STORED but is neutralised by the lock marker."
    fi
fi

echo ""
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
