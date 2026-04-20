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
echo "=== PoC Behavioral Test: Runtime /proc/sys values ==="
# NOTE: In Docker, /proc/sys/ may be read-only and reflect host kernel.
# Check both config AND runtime — fail if EITHER shows the insecure value.

RUNTIME_SYNCOOKIES=$(cat /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null || echo "unavailable")
echo "Runtime tcp_syncookies: $RUNTIME_SYNCOOKIES"
if [ "$RUNTIME_SYNCOOKIES" = "0" ]; then
    if sysctl -w net.ipv4.tcp_syncookies=1 > /dev/null 2>&1; then
        echo "FAIL: tcp_syncookies was 0 at runtime"
        POC_FAIL=1
    else
        echo "WARNING: tcp_syncookies is 0 at runtime but /proc/sys is read-only (Docker limitation — config file check is authoritative)"
    fi
elif [ "$RUNTIME_SYNCOOKIES" != "unavailable" ]; then
    echo "PASS: tcp_syncookies is $RUNTIME_SYNCOOKIES at runtime"
fi

RUNTIME_SRC_ALL=$(cat /proc/sys/net/ipv4/conf/all/accept_source_route 2>/dev/null || echo "unavailable")
echo "Runtime accept_source_route (all): $RUNTIME_SRC_ALL"
if [ "$RUNTIME_SRC_ALL" = "1" ]; then
    if sysctl -w net.ipv4.conf.all.accept_source_route=0 > /dev/null 2>&1; then
        echo "FAIL: accept_source_route (all) was 1 at runtime"
        POC_FAIL=1
    else
        echo "WARNING: accept_source_route (all) is 1 at runtime but /proc/sys is read-only (Docker limitation)"
    fi
elif [ "$RUNTIME_SRC_ALL" != "unavailable" ]; then
    echo "PASS: accept_source_route (all) is $RUNTIME_SRC_ALL at runtime"
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
