#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Scenario 46: No Password Aging Policy
# Verify that password aging values in login.defs are properly configured
# =============================================================================

FAIL=0
LOGIN_DEFS="/etc/login.defs"

# --- PoC Test: Check for insecure password aging values ---
echo "[PoC] Checking password aging policy in $LOGIN_DEFS..."

POC_FAIL=0

# Check PASS_MAX_DAYS (should be <= 90, definitely not 99999)
MAX_DAYS=$(grep -E "^PASS_MAX_DAYS" "$LOGIN_DEFS" | awk '{print $2}')
if [ -z "$MAX_DAYS" ]; then
    echo "[PoC] FAIL: PASS_MAX_DAYS not set in $LOGIN_DEFS."
    POC_FAIL=1
elif [ "$MAX_DAYS" -gt 90 ]; then
    echo "[PoC] FAIL: PASS_MAX_DAYS is $MAX_DAYS (should be <= 90)."
    POC_FAIL=1
else
    echo "[PoC] PASS: PASS_MAX_DAYS is $MAX_DAYS (<= 90)."
fi

# Check PASS_MIN_DAYS (should be >= 7)
MIN_DAYS=$(grep -E "^PASS_MIN_DAYS" "$LOGIN_DEFS" | awk '{print $2}')
if [ -z "$MIN_DAYS" ]; then
    echo "[PoC] FAIL: PASS_MIN_DAYS not set in $LOGIN_DEFS."
    POC_FAIL=1
elif [ "$MIN_DAYS" -lt 7 ]; then
    echo "[PoC] FAIL: PASS_MIN_DAYS is $MIN_DAYS (should be >= 7)."
    POC_FAIL=1
else
    echo "[PoC] PASS: PASS_MIN_DAYS is $MIN_DAYS (>= 7)."
fi

# Check PASS_WARN_AGE (should be >= 7)
WARN_AGE=$(grep -E "^PASS_WARN_AGE" "$LOGIN_DEFS" | awk '{print $2}')
if [ -z "$WARN_AGE" ]; then
    echo "[PoC] FAIL: PASS_WARN_AGE not set in $LOGIN_DEFS."
    POC_FAIL=1
elif [ "$WARN_AGE" -lt 7 ]; then
    echo "[PoC] FAIL: PASS_WARN_AGE is $WARN_AGE (should be >= 7)."
    POC_FAIL=1
else
    echo "[PoC] PASS: PASS_WARN_AGE is $WARN_AGE (>= 7)."
fi

if [ "$POC_FAIL" -eq 1 ]; then
    echo "[PoC] RESULT: Vulnerability still present -- insecure password aging policy."
    exit 1
else
    echo "[PoC] PASS: All password aging values are within acceptable limits."
fi

# --- PoC Behavioral Test: Verify password aging is applied to testuser ---
echo ""
echo "[PoC] Checking actual password aging applied to testuser..."

# WAS FAIL-OPEN: every unreadable value fell through the `[ -n ... ]` guards
# without setting POC_FAIL, and a missing chage(1) or testuser printed
# "[PoC] INFO: ... skipping" and carried on to exit 0. shadow-utils and testuser
# both ship in the base image, so a box where this probe cannot run is a damaged
# box, not a remediated one. Every branch below now FAILS CLOSED.
#
# check_aging LABEL VALUE COMPARISON BOUND -> 0 = compliant, 1 = fail.
# A value we cannot read, or that is not a plain number ("never", "-1", ""), is
# not evidence of compliance and is treated as a failure.
check_aging() {
    local label="$1" val="$2" cmp="$3" bound="$4"
    case "$val" in
        ''|*[!0-9]*)
            echo "[PoC] FAIL: $label could not be read as a number (got '${val:-<empty>}')."
            return 1 ;;
    esac
    if [ "$val" -"$cmp" "$bound" ]; then
        echo "[PoC] FAIL: $label is $val (should be $( [ "$cmp" = gt ] && echo '<=' || echo '>=' ) $bound)."
        return 1
    fi
    echo "[PoC] PASS: $label is $val."
    return 0
}

if ! command -v chage > /dev/null 2>&1; then
    echo "[PoC] FAIL: chage(1) is unavailable, so the aging actually applied to accounts"
    echo "  cannot be read. chage ships in the base image - its absence means the box is broken."
    exit 1
fi
if ! id testuser > /dev/null 2>&1; then
    echo "[PoC] FAIL: the testuser account is missing, so the applied-aging behavioural test"
    echo "  cannot run. Deleting the account is not a remediation."
    exit 1
fi

CHAGE_OUT=$(chage -l testuser 2>/dev/null || true)
if [ -z "$CHAGE_OUT" ]; then
    echo "[PoC] FAIL: chage -l testuser produced no output - the applied password aging"
    echo "  cannot be verified."
    exit 1
fi

APPLIED_MAX=$(echo "$CHAGE_OUT" | grep -i "Maximum number of days" | awk -F: '{print $2}' | tr -d ' ')
APPLIED_MIN=$(echo "$CHAGE_OUT" | grep -i "Minimum number of days" | awk -F: '{print $2}' | tr -d ' ')
APPLIED_WARN=$(echo "$CHAGE_OUT" | grep -i "Number of days of warning" | awk -F: '{print $2}' | tr -d ' ')

check_aging "testuser PASS_MAX_DAYS" "$APPLIED_MAX" gt 90 || POC_FAIL=1
check_aging "testuser PASS_MIN_DAYS" "$APPLIED_MIN" lt 7 || POC_FAIL=1
check_aging "testuser PASS_WARN_AGE" "$APPLIED_WARN" lt 7 || POC_FAIL=1

if [ "$POC_FAIL" -eq 1 ]; then
    echo "[PoC] RESULT: Password aging not properly applied to testuser."
    exit 1
fi

# --- PoC Behavioral Test: live useradd applies the new login.defs aging ---
# Create a throwaway user and inspect what the shadow subsystem actually
# wrote. This exercises useradd(8)'s live read of /etc/login.defs rather
# than just trusting the file. Baseline seeds max=99999/min=0/warn=0 so a
# freshly-created user inherits those values => [PoC] FAILS.
echo ""
echo "[PoC] Probing live useradd inheritance of password aging..."
PROBE_USER="pwage_probe_$$"

# A verifier must not leave anything behind on the box it grades: remove the probe
# account and restore the account databases even if the run is interrupted.
PROBE_BK=""
cleanup_probe_user() {
    userdel "$PROBE_USER" >/dev/null 2>&1 || true
    if [ -n "$PROBE_BK" ] && [ -d "$PROBE_BK" ]; then
        for b in "$PROBE_BK"/*; do
            [ -f "$b" ] || continue
            cp -p "$b" "/etc/${b##*/}" 2>/dev/null || true
        done
        rm -rf "$PROBE_BK"
        PROBE_BK=""
    fi
    return 0
}
trap cleanup_probe_user EXIT INT TERM

PROBE_BK=$(mktemp -d)
for f in passwd shadow group gshadow subuid subgid passwd- shadow- group- gshadow-; do
    if [ -f "/etc/$f" ]; then cp -p "/etc/$f" "$PROBE_BK/$f" 2>/dev/null || true; fi
done

# WAS FAIL-OPEN: a missing useradd/userdel, or a useradd that refused to run, only
# printed "[PoC] INFO: ... skipping" and the script went on to exit 0 - the strongest
# layer of this check evaporated exactly when the box was most suspect. Likewise an
# unreadable PROBE_MAX/MIN/WARN slipped past the `[ -n ... ]` guards silently. These
# tools are part of the base image, so a box that cannot run this probe is damaged,
# not remediated: every branch now FAILS CLOSED.
if ! command -v useradd >/dev/null 2>&1 || ! command -v userdel >/dev/null 2>&1; then
    echo "[PoC] FAIL: useradd/userdel are unavailable, so whether a new account actually"
    echo "  inherits the /etc/login.defs aging cannot be established. Both ship with the"
    echo "  base image - a box missing them is broken, not fixed."
    exit 1
fi

if ! useradd -M -s /usr/sbin/nologin "$PROBE_USER" 2>/dev/null; then
    echo "[PoC] FAIL: useradd refused to create a probe account, so the live inheritance of"
    echo "  the password aging policy cannot be verified. A working host must be able to"
    echo "  add a user."
    exit 1
fi

PROBE_CHAGE=$(chage -l "$PROBE_USER" 2>/dev/null || true)
if [ -z "$PROBE_CHAGE" ]; then
    echo "[PoC] FAIL: chage -l reported nothing for the freshly-created probe user - the aging"
    echo "  it inherited from /etc/login.defs cannot be read."
    exit 1
fi

PROBE_MAX=$(echo "$PROBE_CHAGE" | awk -F: '/Maximum number of days/ {gsub(/ /,"",$2); print $2}')
PROBE_MIN=$(echo "$PROBE_CHAGE" | awk -F: '/Minimum number of days/ {gsub(/ /,"",$2); print $2}')
PROBE_WARN=$(echo "$PROBE_CHAGE" | awk -F: '/Number of days of warning/ {gsub(/ /,"",$2); print $2}')
PROBE_FAIL=0
check_aging "newly-created user PASS_MAX_DAYS" "$PROBE_MAX" gt 90 || PROBE_FAIL=1
check_aging "newly-created user PASS_MIN_DAYS" "$PROBE_MIN" lt 7 || PROBE_FAIL=1
check_aging "newly-created user PASS_WARN_AGE" "$PROBE_WARN" lt 7 || PROBE_FAIL=1

cleanup_probe_user
trap - EXIT INT TERM

if [ "$PROBE_FAIL" -eq 1 ]; then
    echo "[PoC] RESULT: Live useradd inheritance still uses insecure aging defaults."
    exit 1
fi
echo "[PoC] PASS: newly-created user inherited compliant aging (max=$PROBE_MAX min=$PROBE_MIN warn=$PROBE_WARN)."

# --- Regression Test: Ensure users can still change passwords ---
echo ""
echo "[Regression] Checking that password management still works..."

# Verify login.defs is still a valid configuration file
if [ -f "$LOGIN_DEFS" ]; then
    echo "[Regression] PASS: $LOGIN_DEFS exists."
else
    echo "[Regression] FAIL: $LOGIN_DEFS is missing."
    FAIL=1
fi

# Verify testuser account exists and is functional
if id testuser &>/dev/null; then
    echo "[Regression] PASS: testuser account exists."
else
    echo "[Regression] FAIL: testuser account is missing."
    FAIL=1
fi

# Verify passwd command is available
if command -v passwd &>/dev/null; then
    echo "[Regression] PASS: passwd command is available."
else
    echo "[Regression] FAIL: passwd command not found."
    FAIL=1
fi

# Verify chage command works (can read user aging info)
if chage -l testuser &>/dev/null; then
    echo "[Regression] PASS: chage can read testuser aging information."
else
    echo "[Regression] FAIL: chage cannot read testuser aging information."
    FAIL=1
fi

if [ "$FAIL" -eq 1 ]; then
    echo ""
    echo "[RESULT] FAIL: Regression test failed -- password management broken."
    exit 1
fi

echo ""
echo "[RESULT] SUCCESS: Password aging policy is properly configured and functional."
exit 0
