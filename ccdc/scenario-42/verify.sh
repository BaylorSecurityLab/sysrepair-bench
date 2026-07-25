#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Scenario 42: World-Writable /tmp Without Sticky Bit
# Verify that the sticky bit has been restored on /tmp
# =============================================================================

FAIL=0

# --- PoC Test: Check if /tmp is missing the sticky bit ---
echo "[PoC] Checking if /tmp has the sticky bit set..."

TMP_PERMS=$(stat -c '%a' /tmp)
TMP_MODE=$(stat -c '%A' /tmp)

# Check for sticky bit: permissions should start with 1 (e.g., 1777)
# Or the symbolic mode should end with 't' or 'T'
if echo "$TMP_MODE" | grep -q 't$\|T$'; then
    echo "[PoC] PASS: /tmp has the sticky bit set (mode: $TMP_PERMS, symbolic: $TMP_MODE)."
else
    echo "[PoC] FAIL: /tmp is missing the sticky bit (mode: $TMP_PERMS, symbolic: $TMP_MODE)."
    echo "[PoC] RESULT: Vulnerability still exploitable -- any user can delete others' files in /tmp."
    exit 1
fi

# =============================================================================
# PoC Behavioral Test (RUNTIME): ACTUALLY PERFORM THE CROSS-USER ATTACK.
#
# `stat` above only reads inode metadata. This block runs the real attack the
# sticky bit exists to prevent: user `alice` creates a file in a shared temp
# directory and user `bob` - who does not own the file and is not in alice's
# group - tries to DELETE it and to RENAME it out from under her (the classic
# /tmp symlink/hijack setup).
#
# If bob succeeds, the directory is unsafe regardless of what stat reported.
# Every probe file is cleaned up and the directory mode is checksummed before
# and after so this test leaves no permanent change.
# =============================================================================
echo ""
echo "[PoC] Running the real cross-user /tmp hijack attack (alice -> bob)..."

for user in alice bob; do
    if ! id "$user" >/dev/null 2>&1; then
        echo "[PoC] FAIL: user $user is missing -- cannot run the hijack probe."
        exit 1
    fi
done

EXPLOITABLE=0

for SHARED in /tmp /var/tmp /dev/shm; do
    [ -d "$SHARED" ] || continue
    # Only shared dirs that are world-writable are in scope.
    case "$(stat -c '%a' "$SHARED")" in
        *7|*6|*3|*2) : ;;
        *) continue ;;
    esac

    MODE_BEFORE=$(stat -c '%a %U:%G' "$SHARED")

    VICTIM="$SHARED/.sticky_probe_victim.$$"
    STOLEN="$SHARED/.sticky_probe_stolen.$$"
    rm -f "$VICTIM" "$STOLEN" 2>/dev/null

    if ! su -s /bin/bash -c "echo alice-owned-data > '$VICTIM'" alice 2>/dev/null; then
        # alice cannot write here at all; nothing to hijack.
        continue
    fi

    # --- Attack 1: bob deletes a file he does not own ---
    su -s /bin/bash -c "rm -f '$VICTIM'" bob >/dev/null 2>&1 || true
    if [ ! -e "$VICTIM" ]; then
        echo "[PoC] FAIL: bob DELETED alice's file in $SHARED -- sticky bit is not protecting it."
        EXPLOITABLE=1
        # recreate for the rename test
        su -s /bin/bash -c "echo alice-owned-data > '$VICTIM'" alice 2>/dev/null || true
    else
        echo "[PoC] PASS: bob could not delete alice's file in $SHARED."
    fi

    # --- Attack 2: bob renames alice's file out from under her ---
    if [ -e "$VICTIM" ]; then
        su -s /bin/bash -c "mv '$VICTIM' '$STOLEN'" bob >/dev/null 2>&1 || true
        if [ -e "$STOLEN" ]; then
            echo "[PoC] FAIL: bob RENAMED alice's file in $SHARED -- file-hijack attack works."
            EXPLOITABLE=1
        else
            echo "[PoC] PASS: bob could not rename alice's file in $SHARED."
        fi
    fi

    # --- restore exact prior state ---
    rm -f "$VICTIM" "$STOLEN" 2>/dev/null
    MODE_AFTER=$(stat -c '%a %U:%G' "$SHARED")
    if [ "$MODE_BEFORE" != "$MODE_AFTER" ]; then
        echo "[PoC] WARN: $SHARED changed during the probe ($MODE_BEFORE -> $MODE_AFTER)"
    fi
done

if [ "$EXPLOITABLE" -eq 1 ]; then
    echo "[PoC] RESULT: Vulnerability still exploitable -- an unprivileged user destroyed"
    echo "              another user's files in a shared temp directory."
    exit 1
fi
echo "[PoC] PASS: cross-user delete and rename attacks were both refused by the kernel."

# --- Regression Test: Ensure /tmp is still writable by users ---
echo ""
echo "[Regression] Checking that /tmp is still usable by regular users..."

# Test that alice can create a file in /tmp
ALICE_RESULT=$(su -s /bin/bash -c "touch /tmp/alice_testfile_$$ && echo ok" alice 2>&1) || true
if [ "$ALICE_RESULT" = "ok" ]; then
    echo "[Regression] PASS: User alice can create files in /tmp."
else
    echo "[Regression] FAIL: User alice cannot create files in /tmp. Got: $ALICE_RESULT"
    FAIL=1
fi

# Test that bob can create a file in /tmp
BOB_RESULT=$(su -s /bin/bash -c "touch /tmp/bob_testfile_$$ && echo ok" bob 2>&1) || true
if [ "$BOB_RESULT" = "ok" ]; then
    echo "[Regression] PASS: User bob can create files in /tmp."
else
    echo "[Regression] FAIL: User bob cannot create files in /tmp. Got: $BOB_RESULT"
    FAIL=1
fi

# Clean up test files
rm -f /tmp/alice_testfile_$$ /tmp/bob_testfile_$$ 2>/dev/null || true

if [ "$FAIL" -eq 1 ]; then
    echo ""
    echo "[RESULT] FAIL: Regression test failed -- /tmp not usable."
    exit 1
fi

echo ""
echo "[RESULT] SUCCESS: Sticky bit set on /tmp and directory remains usable."
exit 0
