#!/bin/bash
# Scenario 32: Verify AppArmor is installed and enforcing profiles
# Exit 0 = remediation successful, Exit 1 = remediation failed

echo "=== Scenario 32: AppArmor Enforcement Check ==="

# ──────────────────────────────────────────────
# PoC Test: Check if vulnerability still exists
# ──────────────────────────────────────────────
echo "[PoC] Checking if AppArmor is not enforcing..."

# Check 1: Is AppArmor installed?
if ! command -v aa-status &>/dev/null; then
    echo "[PoC] FAIL: AppArmor utilities not installed."
    echo "RESULT: Vulnerability still present (apparmor-utils missing)."
    exit 1
fi
echo "[PoC] PASS: AppArmor utilities are installed."

# Check 2: Is AppArmor service enabled?
if command -v systemctl &>/dev/null; then
    if ! systemctl is-enabled apparmor &>/dev/null 2>&1; then
        echo "[PoC] FAIL: AppArmor service is not enabled."
        echo "RESULT: Vulnerability still present (apparmor not enabled)."
        exit 1
    fi
    echo "[PoC] PASS: AppArmor service is enabled."
fi

# Check 3: Are the shipped profiles actually in enforce mode?
#
# WHAT WAS WRONG (this check used to be a tautology):
#   * The aa-status path did `aa-status | grep -c "enforce"`, which happily
#     matches the literal line "0 profiles are in enforce mode." - i.e. it
#     counted the sentence that says nothing is enforcing as evidence of
#     enforcement.
#   * The on-disk fallback decided a profile was in complain mode only if a
#     /etc/apparmor.d/force-complain/<name> or /etc/apparmor.d/disable/<name>
#     override existed. AppArmor 3.x's aa-complain does NOT use those
#     directories - it rewrites the profile in place, adding `complain` to the
#     profile's flags=(...) list (e.g. `flags=(complain)` or
#     `flags=(attach_disconnected, complain)`). Both directories are empty in
#     this image, so the old fallback reported all ~147 profiles as "enforcing"
#     at BASELINE even though the Dockerfile's aa-complain loop had put every
#     single one of them into complain mode.
#
# The check now reads the real mode: kernel-reported counts via
# `aa-status --count --filter.mode=...` (a bare integer, unspoofable) when
# apparmorfs is mounted, otherwise the profile flags on disk.
ENFORCE_COUNT=0
COMPLAIN_COUNT=0
TOTAL_PROFILES=0
MODE_SOURCE=""

# Preferred: ask the kernel. --count prints a bare number, so there is no text
# for a "0 profiles are in enforce mode." line to be mistaken for.
if AA_ENF=$(aa-status --count --filter.mode=enforce 2>/dev/null) && \
   [[ "$AA_ENF" =~ ^[0-9]+$ ]]; then
    AA_CMP=$(aa-status --count --filter.mode=complain 2>/dev/null)
    [[ "$AA_CMP" =~ ^[0-9]+$ ]] || AA_CMP=0
    ENFORCE_COUNT=$AA_ENF
    COMPLAIN_COUNT=$AA_CMP
    TOTAL_PROFILES=$((ENFORCE_COUNT + COMPLAIN_COUNT))
    MODE_SOURCE="aa-status"
elif [ -d /etc/apparmor.d ]; then
    # Container fallback: apparmorfs is not mounted (aa-status exits 3), so read
    # the mode straight off the policy files that would be loaded at boot.
    for profile in /etc/apparmor.d/*; do
        [ -f "$profile" ] || continue
        base=$(basename "$profile")
        case "$base" in
            local|README|*.md|*.orig|*.dpkg-*) continue ;;
        esac
        TOTAL_PROFILES=$((TOTAL_PROFILES + 1))
        # `complain` anywhere inside a flags=(...) list means non-enforcing.
        # Legacy override directories still count if a solution uses them.
        if grep -qE 'flags[[:space:]]*=[[:space:]]*\([^)]*\bcomplain\b' "$profile" 2>/dev/null || \
           [ -e "/etc/apparmor.d/force-complain/$base" ] || \
           [ -e "/etc/apparmor.d/disable/$base" ]; then
            COMPLAIN_COUNT=$((COMPLAIN_COUNT + 1))
        fi
    done
    ENFORCE_COUNT=$((TOTAL_PROFILES - COMPLAIN_COUNT))
    MODE_SOURCE="/etc/apparmor.d"
fi

# Guard against "remediating" by deleting the policy instead of enforcing it.
# The image ships ~147 profiles; enforcing MAC never means throwing policy away.
if [ "$TOTAL_PROFILES" -lt 10 ]; then
    echo "[PoC] FAIL: Only $TOTAL_PROFILES AppArmor profile(s) present (source: ${MODE_SOURCE:-none})."
    echo "[PoC]       Profiles were removed rather than switched to enforce mode."
    echo "RESULT: Vulnerability still present (AppArmor policy missing)."
    exit 1
fi

if [ "$COMPLAIN_COUNT" -gt 0 ]; then
    echo "[PoC] FAIL: $COMPLAIN_COUNT of $TOTAL_PROFILES AppArmor profile(s) are still in complain mode (source: $MODE_SOURCE)."
    echo "[PoC]       Complain mode only logs; it does not confine anything."
    exit 1
fi

if [ "$ENFORCE_COUNT" -le 0 ]; then
    echo "[PoC] FAIL: No AppArmor profiles are in enforce mode."
    echo "RESULT: Vulnerability still present (no enforced profiles)."
    exit 1
fi
echo "[PoC] PASS: $ENFORCE_COUNT/$TOTAL_PROFILES AppArmor profile(s) in enforce mode (source: $MODE_SOURCE)."

# Check 4: Ensure the intentional-weakness marker is removed or overridden
if [ -f /etc/apparmor/apparmor_status.conf ]; then
    if grep -q "apparmor_disabled=true" /etc/apparmor/apparmor_status.conf 2>/dev/null; then
        echo "[PoC] WARNING: Legacy disable marker found but profiles are enforcing."
    fi
fi

echo "[PoC] All checks passed - vulnerability is remediated."

# ──────────────────────────────────────────────
# Regression Test: Ensure system still works
# ──────────────────────────────────────────────
echo ""
echo "[Regression] Checking system functionality..."

# Check that basic system operations work
if ! id root &>/dev/null; then
    echo "[Regression] FAIL: Basic user operations broken."
    exit 1
fi
echo "[Regression] PASS: User operations work."

# Check that filesystem operations work
TESTFILE="/tmp/apparmor_regression_test_$$"
if ! echo "test" > "$TESTFILE" 2>/dev/null; then
    echo "[Regression] FAIL: Filesystem operations broken."
    exit 1
fi
rm -f "$TESTFILE"
echo "[Regression] PASS: Filesystem operations work."

# Check that process operations work
if ! ps aux &>/dev/null; then
    echo "[Regression] FAIL: Process listing broken."
    exit 1
fi
echo "[Regression] PASS: Process operations work."

# Check that AppArmor itself is not breaking things
if ! ls /etc/ &>/dev/null; then
    echo "[Regression] FAIL: Directory listing broken (possible AppArmor over-restriction)."
    exit 1
fi
echo "[Regression] PASS: AppArmor enforcement does not break normal operations."

# The usual way to flip a profile out of complain mode is to edit its flags=()
# list with sed. A sloppy edit silently corrupts the policy, which would leave
# the host with NO working confinement at the next boot - worse than complain
# mode. Preprocess-and-parse a sample of profiles (-Q parses without loading,
# so it works even though apparmorfs is not mounted in this container).
if command -v apparmor_parser &>/dev/null; then
    PARSE_CHECKED=0
    PARSE_FAILED=0
    for profile in /etc/apparmor.d/*; do
        [ -f "$profile" ] || continue
        case "$(basename "$profile")" in
            local|README|*.md|*.orig|*.dpkg-*) continue ;;
        esac
        PARSE_CHECKED=$((PARSE_CHECKED + 1))
        if ! apparmor_parser -Q "$profile" >/dev/null 2>&1; then
            [ "$PARSE_FAILED" -lt 5 ] && \
                echo "[Regression] FAIL: AppArmor profile $profile no longer parses."
            PARSE_FAILED=$((PARSE_FAILED + 1))
        fi
    done
    if [ "$PARSE_FAILED" -gt 0 ]; then
        echo "[Regression] FAIL: $PARSE_FAILED of $PARSE_CHECKED profiles are syntactically broken."
        exit 1
    fi
    echo "[Regression] PASS: $PARSE_CHECKED AppArmor profiles still parse cleanly."
fi

echo ""
echo "RESULT: Remediation successful - AppArmor enforcing and system functional."
exit 0
