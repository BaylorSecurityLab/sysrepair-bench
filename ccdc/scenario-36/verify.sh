#!/bin/bash
# Scenario 36: Verify CUPS is removed or disabled on server
# Exit 0 = remediation successful, Exit 1 = remediation failed

echo "=== Scenario 36: CUPS Unnecessary Service Check ==="

# ──────────────────────────────────────────────
# PoC Test: Check if vulnerability still exists
# ──────────────────────────────────────────────
echo "[PoC] Checking if CUPS is still installed and enabled..."

# Check 1: Is CUPS still installed?
CUPS_INSTALLED=false
if dpkg -l cups 2>/dev/null | grep -q '^ii'; then
    CUPS_INSTALLED=true
fi

if $CUPS_INSTALLED; then
    # CUPS is installed - check if at least disabled
    echo "[PoC] INFO: cups package is still installed."

    # Check if CUPS service is enabled
    if command -v systemctl &>/dev/null; then
        if systemctl is-enabled cups &>/dev/null 2>&1; then
            echo "[PoC] FAIL: cups service is still enabled."
            echo "RESULT: Vulnerability still present (CUPS enabled)."
            exit 1
        fi
    fi

    echo "[PoC] FAIL: cups package is installed (should be removed on a server)."
    echo "RESULT: Vulnerability still present (CUPS installed)."
    exit 1
fi
echo "[PoC] PASS: cups package is not installed."

# Check 2: Is cups-browsed still installed?
if dpkg -l cups-browsed 2>/dev/null | grep -q '^ii'; then
    echo "[PoC] FAIL: cups-browsed is still installed."
    echo "RESULT: Vulnerability still present (cups-browsed installed)."
    exit 1
fi
echo "[PoC] PASS: cups-browsed package is not installed."

# Check 3: Is anything listening on port 631?
if command -v ss &>/dev/null; then
    if ss -tlnp 2>/dev/null | grep -q ":631 "; then
        echo "[PoC] FAIL: Something is still listening on port 631 (CUPS port)."
        echo "RESULT: Vulnerability still present (port 631 open)."
        exit 1
    fi
    echo "[PoC] PASS: Port 631 is not listening."
elif command -v netstat &>/dev/null; then
    if netstat -tlnp 2>/dev/null | grep -q ":631 "; then
        echo "[PoC] FAIL: Something is still listening on port 631."
        echo "RESULT: Vulnerability still present (port 631 open)."
        exit 1
    fi
    echo "[PoC] PASS: Port 631 is not listening."
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
TESTFILE="/tmp/cups_regression_test_$$"
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

# Check that apt is not broken after package removal
if ! apt-get --version &>/dev/null; then
    echo "[Regression] FAIL: apt-get is broken."
    exit 1
fi
echo "[Regression] PASS: Package manager works."

echo ""
echo "RESULT: Remediation successful - CUPS removed and system functional."
exit 0
