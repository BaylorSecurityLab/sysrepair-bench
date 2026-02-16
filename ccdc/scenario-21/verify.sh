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
