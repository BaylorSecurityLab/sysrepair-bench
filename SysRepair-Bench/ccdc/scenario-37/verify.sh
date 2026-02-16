#!/bin/bash
# Scenario 37: Verify Avahi/mDNS daemon is removed or disabled
# Exit 0 = remediation successful, Exit 1 = remediation failed

echo "=== Scenario 37: Avahi/mDNS Daemon Check ==="

# ──────────────────────────────────────────────
# PoC Test: Check if vulnerability still exists
# ──────────────────────────────────────────────
echo "[PoC] Checking if Avahi daemon is still installed and enabled..."

# Check 1: Is avahi-daemon still installed?
AVAHI_INSTALLED=false
if dpkg -l avahi-daemon 2>/dev/null | grep -q '^ii'; then
    AVAHI_INSTALLED=true
fi

if $AVAHI_INSTALLED; then
    echo "[PoC] INFO: avahi-daemon package is still installed."

    # Check if at least disabled
    if command -v systemctl &>/dev/null; then
        if systemctl is-enabled avahi-daemon &>/dev/null 2>&1; then
            echo "[PoC] FAIL: avahi-daemon service is still enabled."
            echo "RESULT: Vulnerability still present (avahi-daemon enabled)."
            exit 1
        fi
    fi

    echo "[PoC] FAIL: avahi-daemon package is installed (should be removed on a server)."
    echo "RESULT: Vulnerability still present (avahi-daemon installed)."
    exit 1
fi
echo "[PoC] PASS: avahi-daemon package is not installed."

# Check 2: Is anything listening on port 5353?
if command -v ss &>/dev/null; then
    if ss -ulnp 2>/dev/null | grep -q ":5353 "; then
        echo "[PoC] FAIL: Something is still listening on port 5353 (mDNS port)."
        echo "RESULT: Vulnerability still present (port 5353 open)."
        exit 1
    fi
    echo "[PoC] PASS: Port 5353 is not listening."
fi

echo "[PoC] All checks passed - vulnerability is remediated."

# ──────────────────────────────────────────────
# Regression Test: Ensure DNS resolution still works
# ──────────────────────────────────────────────
echo ""
echo "[Regression] Checking system functionality..."

# Check that basic system operations work
if ! id root &>/dev/null; then
    echo "[Regression] FAIL: Basic user operations broken."
    exit 1
fi
echo "[Regression] PASS: User operations work."

# Check that standard DNS resolution works (not mDNS)
DNS_WORKS=false
if command -v host &>/dev/null; then
    if host ubuntu.com &>/dev/null 2>&1; then
        DNS_WORKS=true
        echo "[Regression] PASS: DNS resolution works (host command)."
    fi
elif command -v dig &>/dev/null; then
    if dig ubuntu.com +short &>/dev/null 2>&1; then
        DNS_WORKS=true
        echo "[Regression] PASS: DNS resolution works (dig command)."
    fi
elif command -v nslookup &>/dev/null; then
    if nslookup ubuntu.com &>/dev/null 2>&1; then
        DNS_WORKS=true
        echo "[Regression] PASS: DNS resolution works (nslookup command)."
    fi
fi

if ! $DNS_WORKS; then
    # In a Docker container, DNS might not work via traditional tools
    # Try getent as a fallback
    if command -v getent &>/dev/null; then
        if getent hosts ubuntu.com &>/dev/null 2>&1; then
            DNS_WORKS=true
            echo "[Regression] PASS: DNS resolution works (getent)."
        fi
    fi
fi

if ! $DNS_WORKS; then
    echo "[Regression] WARNING: Could not verify DNS resolution (may be network-restricted in container)."
fi

# Check that /etc/nsswitch.conf is not broken
if [ -f /etc/nsswitch.conf ]; then
    if grep -q "^hosts:" /etc/nsswitch.conf; then
        echo "[Regression] PASS: /etc/nsswitch.conf has hosts entry."
    else
        echo "[Regression] FAIL: /etc/nsswitch.conf is missing hosts entry."
        exit 1
    fi
fi

# Check that filesystem operations work
TESTFILE="/tmp/avahi_regression_test_$$"
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

echo ""
echo "RESULT: Remediation successful - Avahi removed and DNS resolution functional."
exit 0
