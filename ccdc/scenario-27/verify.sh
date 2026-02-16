#!/bin/bash
# Scenario 27: Telnet server running
# Verification: PoC should fail (telnet removed) AND functionality test should pass (SSH available)

PASS=true

# --- PoC Test: Telnet should not be installed or running ---
if dpkg -l telnetd 2>/dev/null | grep -q "^ii"; then
    echo "FAIL [PoC]: telnetd package is still installed"
    PASS=false
else
    echo "PASS [PoC]: telnetd package is removed"
fi

if pgrep -x xinetd > /dev/null 2>&1 || pgrep -f in.telnetd > /dev/null 2>&1; then
    echo "FAIL [PoC]: telnet/xinetd service is still running"
    PASS=false
else
    echo "PASS [PoC]: telnet/xinetd service is not running"
fi

# Check port 23 is not listening
if ss -tlnp 2>/dev/null | grep -q ':23 '; then
    echo "FAIL [PoC]: Port 23 (telnet) is still listening"
    PASS=false
else
    echo "PASS [PoC]: Port 23 is not listening"
fi

# --- Regression Test: SSH should be available as replacement ---
if dpkg -l openssh-server 2>/dev/null | grep -q "^ii"; then
    echo "PASS [Regression]: openssh-server is installed"
else
    echo "FAIL [Regression]: openssh-server is not installed (no secure remote access)"
    PASS=false
fi

# Users should still exist
if id sysadmin > /dev/null 2>&1; then
    echo "PASS [Regression]: sysadmin user still exists"
else
    echo "FAIL [Regression]: sysadmin user is missing"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
