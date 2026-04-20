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
echo "=== PoC Behavioral Test: Runtime /proc/sys values ==="
# NOTE: In Docker, /proc/sys/ may be read-only and reflect host kernel.
# Check both config AND runtime — fail if EITHER shows the insecure value.

RUNTIME_REDIR_ALL=$(cat /proc/sys/net/ipv4/conf/all/accept_redirects 2>/dev/null || echo "unavailable")
echo "Runtime accept_redirects (all): $RUNTIME_REDIR_ALL"
if [ "$RUNTIME_REDIR_ALL" = "1" ]; then
    if sysctl -w net.ipv4.conf.all.accept_redirects=0 > /dev/null 2>&1; then
        echo "FAIL: accept_redirects (all) was 1 at runtime"
        POC_FAIL=1
    else
        echo "WARNING: accept_redirects (all) is 1 at runtime but /proc/sys is read-only (Docker limitation — config file check is authoritative)"
    fi
elif [ "$RUNTIME_REDIR_ALL" != "unavailable" ]; then
    echo "PASS: accept_redirects (all) is $RUNTIME_REDIR_ALL at runtime"
fi

RUNTIME_MART_ALL=$(cat /proc/sys/net/ipv4/conf/all/log_martians 2>/dev/null || echo "unavailable")
echo "Runtime log_martians (all): $RUNTIME_MART_ALL"
if [ "$RUNTIME_MART_ALL" = "0" ]; then
    if sysctl -w net.ipv4.conf.all.log_martians=1 > /dev/null 2>&1; then
        echo "FAIL: log_martians (all) was 0 at runtime"
        POC_FAIL=1
    else
        echo "WARNING: log_martians (all) is 0 at runtime but /proc/sys is read-only (Docker limitation — config file check is authoritative)"
    fi
elif [ "$RUNTIME_MART_ALL" != "unavailable" ]; then
    echo "PASS: log_martians (all) is $RUNTIME_MART_ALL at runtime"
fi

if [ "$POC_FAIL" -eq 1 ]; then
    echo "PoC SUCCEEDED (vulnerability still exists at runtime) - remediation FAILED"
    exit 1
fi

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
