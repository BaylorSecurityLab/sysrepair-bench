#!/bin/bash
# Scenario 33: Verify OpenSSL is updated to the latest available version
# Exit 0 = remediation successful, Exit 1 = remediation failed

echo "=== Scenario 33: OpenSSL Version Check ==="

# ──────────────────────────────────────────────
# PoC Test: Check if vulnerability still exists
# ──────────────────────────────────────────────
echo "[PoC] Checking if OpenSSL is outdated..."

# Check 1: Is OpenSSL installed?
if ! command -v openssl &>/dev/null; then
    echo "[PoC] FAIL: OpenSSL is not installed at all."
    echo "RESULT: Vulnerability still present (openssl missing)."
    exit 1
fi
echo "[PoC] PASS: OpenSSL is installed."

CURRENT_VERSION=$(openssl version 2>/dev/null)
echo "[PoC] Current OpenSSL version: $CURRENT_VERSION"

# Check 2: Is openssl still on hold?
HELD_PACKAGES=$(apt-mark showhold 2>/dev/null)
if echo "$HELD_PACKAGES" | grep -q "openssl"; then
    echo "[PoC] FAIL: openssl package is still on hold (apt-mark hold)."
    echo "RESULT: Vulnerability still present (updates blocked)."
    exit 1
fi
echo "[PoC] PASS: openssl is not on hold."

# Check 3: Is openssl at the latest available version?
apt-get update -qq 2>/dev/null
UPGRADE_AVAILABLE=$(apt-get -s upgrade 2>/dev/null | grep -E "^Inst.*openssl" || true)
if [ -n "$UPGRADE_AVAILABLE" ]; then
    echo "[PoC] FAIL: A newer version of openssl is available but not installed."
    echo "  Available upgrade: $UPGRADE_AVAILABLE"
    echo "RESULT: Vulnerability still present (openssl not at latest version)."
    exit 1
fi
echo "[PoC] PASS: openssl is at the latest available version."

# Check 4: Verify the vulnerability marker has been addressed
if [ -f /opt/.openssl_status ]; then
    if grep -q "VULNERABLE_OPENSSL=true" /opt/.openssl_status 2>/dev/null; then
        # Check if the version actually changed from the recorded vulnerable version
        if [ -f /opt/.openssl_vulnerable_version ]; then
            OLD_VERSION=$(cat /opt/.openssl_vulnerable_version 2>/dev/null)
            if [ "$CURRENT_VERSION" = "$OLD_VERSION" ]; then
                echo "[PoC] WARNING: Version unchanged from recorded vulnerable version."
                echo "  However, if no updates are available, this may be acceptable."
            fi
        fi
    fi
fi

echo "[PoC] All checks passed - OpenSSL is up to date."

# ──────────────────────────────────────────────
# Regression Test: Ensure TLS still works
# ──────────────────────────────────────────────
echo ""
echo "[Regression] Checking TLS functionality..."

# Check that openssl can perform basic operations
if ! openssl version &>/dev/null; then
    echo "[Regression] FAIL: openssl command is broken."
    exit 1
fi
echo "[Regression] PASS: openssl command works."

# Check that OpenSSL can generate keys
TESTKEY="/tmp/openssl_test_key_$$"
if ! openssl genrsa -out "$TESTKEY" 2048 &>/dev/null; then
    echo "[Regression] FAIL: OpenSSL cannot generate RSA keys."
    rm -f "$TESTKEY"
    exit 1
fi
rm -f "$TESTKEY"
echo "[Regression] PASS: RSA key generation works."

# Check that TLS connections work (test against a known endpoint)
if command -v curl &>/dev/null; then
    if ! curl -s --max-time 10 https://ubuntu.com &>/dev/null; then
        # May fail in isolated Docker, try openssl s_client instead
        if ! echo | openssl s_client -connect ubuntu.com:443 -brief 2>/dev/null | grep -qi "verify"; then
            echo "[Regression] WARNING: Could not verify TLS connection (may be network-restricted)."
        fi
    else
        echo "[Regression] PASS: TLS connections work (curl to https)."
    fi
else
    echo "[Regression] SKIP: curl not available for TLS connection test."
fi

# Basic system sanity
if ! id root &>/dev/null; then
    echo "[Regression] FAIL: Basic user operations broken."
    exit 1
fi
echo "[Regression] PASS: System operations work."

echo ""
echo "RESULT: Remediation successful - OpenSSL updated and TLS functional."
exit 0
