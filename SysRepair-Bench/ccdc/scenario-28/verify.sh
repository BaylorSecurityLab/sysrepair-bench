#!/bin/bash
# Scenario 28: rsh/rlogin services enabled
# Verification: PoC should fail (rsh removed) AND functionality test should pass

PASS=true

# --- PoC Test: rsh-server should not be installed ---
if dpkg -l rsh-server 2>/dev/null | grep -q "^ii"; then
    echo "FAIL [PoC]: rsh-server package is still installed"
    PASS=false
else
    echo "PASS [PoC]: rsh-server package is removed"
fi

# Check rsh/rlogin processes
if pgrep -f 'in.rshd\|in.rlogind' > /dev/null 2>&1; then
    echo "FAIL [PoC]: rsh/rlogin processes are still running"
    PASS=false
else
    echo "PASS [PoC]: rsh/rlogin processes are not running"
fi

# Check .rhosts files
if [ -f /root/.rhosts ]; then
    echo "FAIL [PoC]: /root/.rhosts still exists"
    PASS=false
else
    echo "PASS [PoC]: /root/.rhosts is removed"
fi

# Check for .rhosts in home directories
RHOSTS_FOUND=$(find /home -name .rhosts 2>/dev/null)
if [ -n "$RHOSTS_FOUND" ]; then
    echo "FAIL [PoC]: .rhosts files found in home directories: $RHOSTS_FOUND"
    PASS=false
else
    echo "PASS [PoC]: No .rhosts files in home directories"
fi

# --- Regression Test: Users should still exist ---
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
