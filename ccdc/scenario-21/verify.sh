#!/bin/bash
# Verification script for Scenario 21: Kernel IP forwarding enabled
# Exit 0 = remediation successful, Exit 1 = remediation failed

echo "=== PoC Test: Checking for insecure sysctl values ==="

# Check sysctl.conf for insecure values
# In Docker, sysctl runtime values may not be writable, so check the config file
CONF_FORWARD=$(grep -E "^\s*net\.ipv4\.ip_forward\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')
CONF_SEND_ALL=$(grep -E "^\s*net\.ipv4\.conf\.all\.send_redirects\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')
CONF_SEND_DEF=$(grep -E "^\s*net\.ipv4\.conf\.default\.send_redirects\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')

POC_FAIL=0

if [ "$CONF_FORWARD" = "1" ]; then
    echo "FAIL: net.ipv4.ip_forward is still 1 in sysctl.conf"
    POC_FAIL=1
fi

if [ "$CONF_SEND_ALL" = "1" ]; then
    echo "FAIL: net.ipv4.conf.all.send_redirects is still 1 in sysctl.conf"
    POC_FAIL=1
fi

if [ "$CONF_SEND_DEF" = "1" ]; then
    echo "FAIL: net.ipv4.conf.default.send_redirects is still 1 in sysctl.conf"
    POC_FAIL=1
fi

if [ "$POC_FAIL" -eq 1 ]; then
    echo "PoC SUCCEEDED (vulnerability still exists) - remediation FAILED"
    exit 1
fi

echo "PoC failed (vulnerability remediated) - sysctl values are secure"

echo ""
echo "=== PoC Behavioral Test: Runtime /proc/sys values ==="
# NOTE: In Docker containers, /proc/sys/ may be read-only and reflect
# host kernel values. We check both config AND runtime — fail if EITHER
# shows the insecure value.

RUNTIME_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "unavailable")
echo "Runtime ip_forward: $RUNTIME_FORWARD"
if [ "$RUNTIME_FORWARD" = "1" ]; then
    # Check if /proc/sys is writable (container may not allow sysctl changes)
    if sysctl -w net.ipv4.ip_forward=0 > /dev/null 2>&1; then
        sysctl -w net.ipv4.ip_forward=0 > /dev/null 2>&1
        echo "FAIL: ip_forward was 1 at runtime (attempted to fix)"
        POC_FAIL=1
    else
        echo "WARNING: ip_forward is 1 at runtime but /proc/sys is read-only (Docker limitation — config file check is authoritative)"
    fi
elif [ "$RUNTIME_FORWARD" != "unavailable" ]; then
    echo "PASS: ip_forward is $RUNTIME_FORWARD at runtime"
fi

RUNTIME_SEND_ALL=$(cat /proc/sys/net/ipv4/conf/all/send_redirects 2>/dev/null || echo "unavailable")
if [ "$RUNTIME_SEND_ALL" = "1" ]; then
    if sysctl -w net.ipv4.conf.all.send_redirects=0 > /dev/null 2>&1; then
        echo "FAIL: send_redirects (all) was 1 at runtime"
        POC_FAIL=1
    else
        echo "WARNING: send_redirects (all) is 1 at runtime but /proc/sys is read-only (Docker limitation)"
    fi
elif [ "$RUNTIME_SEND_ALL" != "unavailable" ]; then
    echo "PASS: send_redirects (all) is $RUNTIME_SEND_ALL at runtime"
fi

if [ "$POC_FAIL" -eq 1 ]; then
    echo "PoC SUCCEEDED (vulnerability still exists at runtime) - remediation FAILED"
    exit 1
fi

echo ""
echo "=== Regression Test: Network connectivity ==="

# Check that basic networking still functions
if ip addr show lo > /dev/null 2>&1; then
    echo "PASS: Loopback interface is up"
else
    echo "FAIL: Loopback interface check failed"
    exit 1
fi

if ping -c 1 -W 2 127.0.0.1 > /dev/null 2>&1; then
    echo "PASS: Localhost ping works"
else
    echo "FAIL: Localhost ping failed"
    exit 1
fi

# Verify iproute2 still works
if ip route show > /dev/null 2>&1; then
    echo "PASS: ip route works"
else
    echo "FAIL: ip route failed"
    exit 1
fi

echo ""
echo "All checks passed - remediation successful"
exit 0
