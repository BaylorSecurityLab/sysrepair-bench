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

# Check 2: Is openssl (or its runtime library) still pinned?
# WAS WEAK: only the literal string "openssl" was matched, so a remaining hold
# on libssl3t64/libssl3 - which is where the actual TLS code lives - went
# unnoticed. Also catch apt preference pins, which block updates just as well.
HELD_PACKAGES=$(apt-mark showhold 2>/dev/null)
if echo "$HELD_PACKAGES" | grep -qE '(^|[[:space:]])(openssl|libssl[0-9a-z]*)([[:space:]]|$)'; then
    echo "[PoC] FAIL: openssl/libssl package is still on hold (apt-mark hold): $(echo "$HELD_PACKAGES" | tr '\n' ' ')"
    echo "RESULT: Vulnerability still present (updates blocked)."
    exit 1
fi
echo "[PoC] PASS: openssl and its libssl runtime are not on hold."

if grep -rqsiE '^\s*Package:.*(openssl|libssl)' /etc/apt/preferences /etc/apt/preferences.d 2>/dev/null; then
    if grep -rqsiE '^\s*Pin-Priority:\s*-?[0-9]+' /etc/apt/preferences /etc/apt/preferences.d 2>/dev/null; then
        echo "[PoC] FAIL: an apt preferences pin still constrains openssl/libssl."
        echo "RESULT: Vulnerability still present (updates blocked by apt pin)."
        exit 1
    fi
fi
echo "[PoC] PASS: no apt preference pin constrains openssl/libssl."

# Check 3: Is openssl at the latest available version?
# WAS WEAK: the image ships with /var/lib/apt/lists wiped, so if `apt-get update`
# silently failed, `apt-get -s upgrade` had no candidate data and the check
# passed vacuously - a stale, held openssl would have looked "latest".
# Now the apt cache must demonstrably be populated before the conclusion counts.
apt_update_ok() {
    # apt-get update exits 0 even when every index fails to download.
    apt-get update -qq >/tmp/aptupd.$$.log 2>&1 || return 1
    grep -qE '(Failed to fetch|Some index files failed to download)' /tmp/aptupd.$$.log && return 1
    return 0
}
if ! apt_update_ok; then
    sleep 5
    if ! apt_update_ok; then
        echo "[PoC] FAIL: apt-get update failed - cannot establish whether openssl is current."
        tail -3 /tmp/aptupd.$$.log
        rm -f /tmp/aptupd.$$.log
        echo "RESULT: Cannot verify remediation (no package index)."
        exit 1
    fi
fi
rm -f /tmp/aptupd.$$.log

OPENSSL_POLICY=$(apt-cache policy openssl 2>/dev/null)
CANDIDATE=$(echo "$OPENSSL_POLICY" | awk '/Candidate:/{print $2}')
INSTALLED=$(echo "$OPENSSL_POLICY" | awk '/Installed:/{print $2}')
if [ -z "$CANDIDATE" ] || [ "$CANDIDATE" = "(none)" ]; then
    echo "[PoC] FAIL: apt has no candidate version for openssl - the package index is empty,"
    echo "  so 'no upgrade pending' would be a meaningless conclusion."
    echo "RESULT: Cannot verify remediation (empty package index)."
    exit 1
fi
if [ "$INSTALLED" != "$CANDIDATE" ]; then
    echo "[PoC] FAIL: installed openssl ($INSTALLED) is not the archive candidate ($CANDIDATE)."
    echo "RESULT: Vulnerability still present (openssl not at latest version)."
    exit 1
fi

UPGRADE_AVAILABLE=$(apt-get -s upgrade 2>/dev/null | grep -E "^Inst.*(openssl|libssl)" || true)
if [ -n "$UPGRADE_AVAILABLE" ]; then
    echo "[PoC] FAIL: A newer version of openssl/libssl is available but not installed."
    echo "  Available upgrade: $UPGRADE_AVAILABLE"
    echo "RESULT: Vulnerability still present (openssl not at latest version)."
    exit 1
fi
echo "[PoC] PASS: openssl is at the latest available version (installed=$INSTALLED, candidate=$CANDIDATE)."

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

# --- Real TLS handshake regression -------------------------------------------
# WAS WEAK: every TLS failure here was downgraded to a WARNING, so an openssl
# "upgrade" that left a broken libssl (or a mangled /etc/ssl/openssl.cnf) still
# passed. This handshake is hermetic - s_server and s_client on loopback - so it
# does not depend on outbound network and a failure is a genuine regression.
TLSDIR=$(mktemp -d /tmp/tlsreg.XXXXXX)
TLS_OK=false
if openssl req -x509 -newkey rsa:2048 -keyout "$TLSDIR/k.pem" -out "$TLSDIR/c.pem" \
        -days 1 -nodes -subj "/CN=localhost" >/dev/null 2>&1; then
    openssl s_server -quiet -key "$TLSDIR/k.pem" -cert "$TLSDIR/c.pem" \
        -accept 14433 -naccept 1 >/dev/null 2>&1 &
    SRV_PID=$!
    sleep 2
    if echo Q | timeout 15 openssl s_client -connect 127.0.0.1:14433 -brief 2>&1 \
            | grep -q "CONNECTION ESTABLISHED"; then
        TLS_OK=true
    fi
    kill "$SRV_PID" 2>/dev/null || true
    wait "$SRV_PID" 2>/dev/null || true
else
    echo "[Regression] FAIL: openssl cannot generate a self-signed certificate."
fi
rm -rf "$TLSDIR"

if $TLS_OK; then
    echo "[Regression] PASS: local TLS handshake succeeded (libssl is functional)."
else
    echo "[Regression] FAIL: local TLS handshake failed - the TLS stack is broken."
    exit 1
fi

# Outbound TLS is a bonus signal only (containers may be network-restricted).
if command -v curl &>/dev/null; then
    if curl -s --max-time 10 https://ubuntu.com &>/dev/null; then
        echo "[Regression] PASS: outbound TLS connections work (curl to https)."
    else
        echo "[Regression] INFO: outbound https unavailable (network-restricted)."
    fi
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
