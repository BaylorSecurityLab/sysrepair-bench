#!/bin/bash
# Verification script for Scenario 23: SYN cookies disabled + source routing accepted
# Exit 0 = remediation successful, Exit 1 = remediation failed

echo "=== PoC Test: Checking for insecure sysctl values ==="

# Read config file values
CONF_SYNCOOKIES=$(grep -E "^\s*net\.ipv4\.tcp_syncookies\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')
CONF_SRC_ROUTE_ALL=$(grep -E "^\s*net\.ipv4\.conf\.all\.accept_source_route\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')
CONF_SRC_ROUTE_DEF=$(grep -E "^\s*net\.ipv4\.conf\.default\.accept_source_route\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')

POC_FAIL=0

if [ "$CONF_SYNCOOKIES" = "0" ]; then
    echo "FAIL: tcp_syncookies is still 0 in sysctl.conf"
    POC_FAIL=1
fi

if [ "$CONF_SRC_ROUTE_ALL" = "1" ]; then
    echo "FAIL: conf.all.accept_source_route is still 1 in sysctl.conf"
    POC_FAIL=1
fi

if [ "$CONF_SRC_ROUTE_DEF" = "1" ]; then
    echo "FAIL: conf.default.accept_source_route is still 1 in sysctl.conf"
    POC_FAIL=1
fi

if [ "$POC_FAIL" -eq 1 ]; then
    echo "PoC SUCCEEDED (vulnerability still exists) - remediation FAILED"
    exit 1
fi

echo "PoC failed (vulnerability remediated) - sysctl values are secure"

echo ""
echo "=== Regression Test: Network connectivity ==="

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

if ip route show > /dev/null 2>&1; then
    echo "PASS: Routing table accessible"
else
    echo "FAIL: Cannot access routing table"
    exit 1
fi

echo ""
echo "All checks passed - remediation successful"
exit 0
