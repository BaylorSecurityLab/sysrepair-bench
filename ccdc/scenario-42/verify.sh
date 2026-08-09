#!/usr/bin/env bash
set -euo pipefail

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# =============================================================================
# Scenario 42: World-Writable /tmp Without Sticky Bit
# Verify that the sticky bit has been restored on /tmp
#
# PoC checks:        /tmp carries the sticky bit and a real cross-user delete /
#                    rename hijack in the shared temp dirs is refused
# Regression checks: ordinary users can still create files in /tmp
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
# Exit 42 = precondition does not hold on this host
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "set the sticky bit but made /tmp unusable" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.
# =============================================================================

# --- PoC Test: Check if /tmp is missing the sticky bit ---
echo "[PoC] Checking if /tmp has the sticky bit set..."

TMP_PERMS=$(stat -c '%a' /tmp || true)
TMP_MODE=$(stat -c '%A' /tmp || true)

# Check for sticky bit: permissions should start with 1 (e.g., 1777)
# Or the symbolic mode should end with 't' or 'T'
if echo "$TMP_MODE" | grep -q 't$\|T$'; then
    record_poc tmp_sticky_bit_set 1
else
    record_poc tmp_sticky_bit_set 0 "/tmp is missing the sticky bit (mode: ${TMP_PERMS:-unknown}, symbolic: ${TMP_MODE:-unknown}) -- any user can delete others' files in /tmp"
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

PROBE_USERS_OK=1
MISSING_USERS=""
for user in alice bob; do
    if ! id "$user" >/dev/null 2>&1; then
        MISSING_USERS="${MISSING_USERS}${MISSING_USERS:+, }$user"
        PROBE_USERS_OK=0
    fi
done
if [ "$PROBE_USERS_OK" -eq 1 ]; then
    record_poc hijack_probe_accounts_present 1
else
    record_poc hijack_probe_accounts_present 0 "user(s) $MISSING_USERS missing -- cannot run the hijack probe"
fi

DELETE_HIJACKED=""
RENAME_HIJACKED=""

if [ "$PROBE_USERS_OK" -eq 1 ]; then
    for SHARED in /tmp /var/tmp /dev/shm; do
        [ -d "$SHARED" ] || continue
        # Only shared dirs that are world-writable are in scope.
        case "$(stat -c '%a' "$SHARED" || true)" in
            *7|*6|*3|*2) : ;;
            *) continue ;;
        esac

        MODE_BEFORE=$(stat -c '%a %U:%G' "$SHARED" || true)

        VICTIM="$SHARED/.sticky_probe_victim.$$"
        STOLEN="$SHARED/.sticky_probe_stolen.$$"
        rm -f "$VICTIM" "$STOLEN" 2>/dev/null || true

        if ! su -s /bin/bash -c "echo alice-owned-data > '$VICTIM'" alice 2>/dev/null; then
            # alice cannot write here at all; nothing to hijack.
            continue
        fi

        # --- Attack 1: bob deletes a file he does not own ---
        su -s /bin/bash -c "rm -f '$VICTIM'" bob >/dev/null 2>&1 || true
        if [ ! -e "$VICTIM" ]; then
            echo "  [PoC] bob DELETED alice's file in $SHARED -- sticky bit is not protecting it."
            DELETE_HIJACKED="${DELETE_HIJACKED}${DELETE_HIJACKED:+, }$SHARED"
            # recreate for the rename test
            su -s /bin/bash -c "echo alice-owned-data > '$VICTIM'" alice 2>/dev/null || true
        else
            echo "  [PoC] bob could not delete alice's file in $SHARED."
        fi

        # --- Attack 2: bob renames alice's file out from under her ---
        if [ -e "$VICTIM" ]; then
            su -s /bin/bash -c "mv '$VICTIM' '$STOLEN'" bob >/dev/null 2>&1 || true
            if [ -e "$STOLEN" ]; then
                echo "  [PoC] bob RENAMED alice's file in $SHARED -- file-hijack attack works."
                RENAME_HIJACKED="${RENAME_HIJACKED}${RENAME_HIJACKED:+, }$SHARED"
            else
                echo "  [PoC] bob could not rename alice's file in $SHARED."
            fi
        fi

        # --- restore exact prior state ---
        rm -f "$VICTIM" "$STOLEN" 2>/dev/null || true
        MODE_AFTER=$(stat -c '%a %U:%G' "$SHARED" || true)
        if [ "$MODE_BEFORE" != "$MODE_AFTER" ]; then
            echo "[PoC] WARN: $SHARED changed during the probe ($MODE_BEFORE -> $MODE_AFTER)"
        fi
    done
fi

if [ -n "$DELETE_HIJACKED" ]; then
    record_poc cross_user_delete_refused 0 "an unprivileged user deleted another user's file in: $DELETE_HIJACKED"
else
    record_poc cross_user_delete_refused 1
fi

if [ -n "$RENAME_HIJACKED" ]; then
    record_poc cross_user_rename_refused 0 "an unprivileged user renamed another user's file in: $RENAME_HIJACKED"
else
    record_poc cross_user_rename_refused 1
fi

# --- Regression Test: Ensure /tmp is still writable by users ---
echo ""
echo "[Regression] Checking that /tmp is still usable by regular users..."

# Test that alice can create a file in /tmp
ALICE_RESULT=$(su -s /bin/bash -c "touch /tmp/alice_testfile_$$ && echo ok" alice 2>&1) || true
if [ "$ALICE_RESULT" = "ok" ]; then
    record_reg alice_can_create_files_in_tmp 1
else
    record_reg alice_can_create_files_in_tmp 0 "user alice cannot create files in /tmp. Got: $ALICE_RESULT"
fi

# Test that bob can create a file in /tmp
BOB_RESULT=$(su -s /bin/bash -c "touch /tmp/bob_testfile_$$ && echo ok" bob 2>&1) || true
if [ "$BOB_RESULT" = "ok" ]; then
    record_reg bob_can_create_files_in_tmp 1
else
    record_reg bob_can_create_files_in_tmp 0 "user bob cannot create files in /tmp. Got: $BOB_RESULT"
fi

# Clean up test files
rm -f /tmp/alice_testfile_$$ /tmp/bob_testfile_$$ 2>/dev/null || true

verify_finish
