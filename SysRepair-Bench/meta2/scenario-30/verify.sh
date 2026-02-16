#!/bin/bash

set -e

echo "=== Scenario 30: Telnet Service Cleartext Login Verification ==="

# Check 1: Verify telnet port 23 is NOT listening (PoC - vulnerability should be gone)
if netstat -ln | grep -q ":23 "; then
    echo "FAIL: Telnet port 23 is still listening"
    exit 1
fi

echo "OK: Telnet port 23 is not listening"

# Check 2: Verify telnet service is disabled in xinetd (if xinetd still exists)
if [ -f /etc/xinetd.d/telnet ]; then
    if grep -q "disable.*=.*no" /etc/xinetd.d/telnet; then
        echo "FAIL: Telnet is still enabled in xinetd configuration"
        exit 1
    fi
    echo "OK: Telnet is disabled in xinetd configuration"
elif dpkg -l | grep -q telnetd; then
    echo "FAIL: Telnetd package is still installed but should be removed"
    exit 1
else
    echo "OK: Telnetd package is removed"
fi

# Check 3: Verify SSH is available as replacement (Regression - service should work)
if ! netstat -ln | grep -q ":22 "; then
    echo "FAIL: SSH port 22 is not listening (no secure alternative available)"
    exit 1
fi

echo "OK: SSH port 22 is listening"

# Check 4: Verify SSH service is operational
if ! ps aux | grep -v grep | grep -q sshd; then
    echo "FAIL: SSH daemon is not running"
    exit 1
fi

echo "OK: SSH daemon is running"

echo "=== PASS: Vulnerability remediated, secure alternative (SSH) available ==="
exit 0
