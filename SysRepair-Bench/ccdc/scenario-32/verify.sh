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

# Check 3: Are any profiles in enforce mode?
# aa-status may need root; check profile files as fallback
ENFORCE_COUNT=0

# Try aa-status first
if aa-status &>/dev/null 2>&1; then
    ENFORCE_COUNT=$(aa-status 2>/dev/null | grep -c "enforce" || echo "0")
fi

# Fallback: check if profiles are not in complain mode on disk
if [ "$ENFORCE_COUNT" -eq 0 ] && [ -d /etc/apparmor.d ]; then
    # Count profiles that exist and are NOT symlinked to complain mode
    TOTAL_PROFILES=0
    COMPLAIN_PROFILES=0
    for profile in /etc/apparmor.d/*; do
        if [ -f "$profile" ] && ! echo "$profile" | grep -qE '(local|abstractions|tunables|force-complain|disable)'; then
            TOTAL_PROFILES=$((TOTAL_PROFILES + 1))
            # Check if there is a complain-mode flag for this profile
            if [ -e "/etc/apparmor.d/force-complain/$(basename "$profile")" ] || \
               [ -e "/etc/apparmor.d/disable/$(basename "$profile")" ]; then
                COMPLAIN_PROFILES=$((COMPLAIN_PROFILES + 1))
            fi
        fi
    done
    ENFORCE_COUNT=$((TOTAL_PROFILES - COMPLAIN_PROFILES))
fi

if [ "$ENFORCE_COUNT" -le 0 ]; then
    echo "[PoC] FAIL: No AppArmor profiles are in enforce mode."
    echo "RESULT: Vulnerability still present (no enforced profiles)."
    exit 1
fi
echo "[PoC] PASS: $ENFORCE_COUNT AppArmor profile(s) in enforce mode."

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

echo ""
echo "RESULT: Remediation successful - AppArmor enforcing and system functional."
exit 0
