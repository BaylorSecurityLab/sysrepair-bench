#!/bin/bash

set -e

echo "=== Scenario 32: Ingreslock Backdoor Verification ==="

# Check 1: Verify port 1524 is NOT listening (PoC - backdoor should be gone)
if netstat -ln 2>/dev/null | grep -q ":1524 " || \
   lsof -i :1524 2>/dev/null | grep -q LISTEN; then
    echo "FAIL: Port 1524 is still listening (backdoor active)"
    exit 1
fi

echo "OK: Port 1524 is not listening"

# Check 2: Verify the backdoor script is removed
if [ -f /opt/ingreslock_backdoor.sh ]; then
    echo "FAIL: Backdoor script still exists at /opt/ingreslock_backdoor.sh"
    exit 1
fi

echo "OK: Backdoor script is removed"

# Check 3: Verify no suspicious netcat processes are running on port 1524
NC_PROCS=$(ps aux | grep -v grep | grep "nc.*1524" || true)
if [ -n "$NC_PROCS" ]; then
    echo "FAIL: Netcat process still running on port 1524: $NC_PROCS"
    exit 1
fi

echo "OK: No netcat processes listening on port 1524"

# Check 4: Verify firewall rule blocks port 1524 (if iptables is configured)
if command -v iptables >/dev/null 2>&1; then
    if iptables -L INPUT -n 2>/dev/null | grep -q "dpt:1524.*DROP\|dpt:1524.*REJECT"; then
        echo "OK: Firewall rule blocks port 1524"
    else
        echo "WARNING: No firewall rule found blocking port 1524 (acceptable if service is removed)"
    fi
fi

# Check 5: Verify system is otherwise operational - SSH should work
if ! netstat -ln | grep -q ":22 "; then
    echo "FAIL: SSH port 22 is not listening (system may be broken)"
    exit 1
fi

echo "OK: SSH port 22 is listening"

if ! ps aux | grep -v grep | grep -q sshd; then
    echo "FAIL: SSH daemon is not running"
    exit 1
fi

echo "OK: SSH daemon is running"

echo "=== PASS: Backdoor removed, system operational ==="
exit 0
