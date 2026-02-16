#!/bin/bash

set -e

echo "=== Scenario 31: rlogin Passwordless Service Verification ==="

# Check 1: Verify rlogin port 513 is NOT listening (PoC - vulnerability should be gone)
if netstat -ln | grep -q ":513 "; then
    echo "FAIL: rlogin port 513 is still listening"
    exit 1
fi

echo "OK: rlogin port 513 is not listening"

# Check 2: Verify rsh-server package is removed
if dpkg -l | grep -q "^ii.*rsh-server"; then
    echo "FAIL: rsh-server package is still installed"
    exit 1
fi

echo "OK: rsh-server package is removed"

# Check 3: Verify dangerous trust files are removed
if [ -f /etc/hosts.equiv ]; then
    echo "FAIL: /etc/hosts.equiv still exists"
    exit 1
fi

echo "OK: /etc/hosts.equiv removed"

# Check for .rhosts files in common locations
RHOSTS_FOUND=$(find /root /home -name .rhosts 2>/dev/null || true)
if [ -n "$RHOSTS_FOUND" ]; then
    echo "FAIL: .rhosts files still exist: $RHOSTS_FOUND"
    exit 1
fi

echo "OK: No .rhosts files found"

# Check 4: Verify SSH is available as replacement (Regression - service should work)
if ! netstat -ln | grep -q ":22 "; then
    echo "FAIL: SSH port 22 is not listening (no secure alternative available)"
    exit 1
fi

echo "OK: SSH port 22 is listening"

# Check 5: Verify SSH service is operational
if ! ps aux | grep -v grep | grep -q sshd; then
    echo "FAIL: SSH daemon is not running"
    exit 1
fi

echo "OK: SSH daemon is running"

echo "=== PASS: Vulnerability remediated, secure alternative (SSH) available ==="
exit 0
