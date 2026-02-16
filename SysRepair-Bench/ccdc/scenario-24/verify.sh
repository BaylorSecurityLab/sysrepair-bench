#!/bin/bash
# Verification script for Scenario 24: ICMP redirects accepted + martians not logged
# Exit 0 = remediation successful, Exit 1 = remediation failed

echo "=== PoC Test: Checking for insecure sysctl values ==="

# Read config file values
CONF_REDIR_ALL=$(grep -E "^\s*net\.ipv4\.conf\.all\.accept_redirects\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')
CONF_REDIR_DEF=$(grep -E "^\s*net\.ipv4\.conf\.default\.accept_redirects\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')
CONF_MART_ALL=$(grep -E "^\s*net\.ipv4\.conf\.all\.log_martians\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')
CONF_MART_DEF=$(grep -E "^\s*net\.ipv4\.conf\.default\.log_martians\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')

POC_FAIL=0

if [ "$CONF_REDIR_ALL" = "1" ]; then
    echo "FAIL: conf.all.accept_redirects is still 1"
    POC_FAIL=1
fi

if [ "$CONF_REDIR_DEF" = "1" ]; then
    echo "FAIL: conf.default.accept_redirects is still 1"
    POC_FAIL=1
fi

if [ "$CONF_MART_ALL" = "0" ]; then
    echo "FAIL: conf.all.log_martians is still 0"
    POC_FAIL=1
fi

if [ "$CONF_MART_DEF" = "0" ]; then
    echo "FAIL: conf.default.log_martians is still 0"
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
