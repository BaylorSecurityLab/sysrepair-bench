#!/bin/bash
# Scenario 39: /etc/shadow world-readable
# Verification: PoC should fail (shadow not readable) AND functionality test should pass

PASS=true

# --- PoC Test: /etc/shadow should not be world-readable ---
PERMS=$(stat -c "%a" /etc/shadow 2>/dev/null)
OWNER=$(stat -c "%U:%G" /etc/shadow 2>/dev/null)

# Check that others can't read it (last digit should be 0)
OTHERS_PERM=${PERMS: -1}
if [[ "$OTHERS_PERM" != "0" ]]; then
    echo "FAIL [PoC]: /etc/shadow is world-readable (permissions: $PERMS)"
    PASS=false
else
    echo "PASS [PoC]: /etc/shadow is not world-readable (permissions: $PERMS)"
fi

# Check permissions are correct (should be 640 or 600)
if [[ "$PERMS" == "640" ]] || [[ "$PERMS" == "600" ]]; then
    echo "PASS [PoC]: /etc/shadow has correct permissions ($PERMS)"
else
    echo "FAIL [PoC]: /etc/shadow has unexpected permissions ($PERMS, expected 640 or 600)"
    PASS=false
fi

# Check ownership
if [[ "$OWNER" == "root:shadow" ]] || [[ "$OWNER" == "root:root" ]]; then
    echo "PASS [PoC]: /etc/shadow ownership is correct ($OWNER)"
else
    echo "FAIL [PoC]: /etc/shadow has wrong ownership ($OWNER)"
    PASS=false
fi

# --- Regression Test: Authentication should still work ---
# Check that users can still be looked up
if id sysadmin > /dev/null 2>&1; then
    echo "PASS [Regression]: User lookup works"
else
    echo "FAIL [Regression]: User lookup failed"
    PASS=false
fi

# Check sshd can still start
if pgrep -x sshd > /dev/null 2>&1; then
    echo "PASS [Regression]: sshd is running"
else
    /usr/sbin/sshd 2>/dev/null
    if pgrep -x sshd > /dev/null 2>&1; then
        echo "PASS [Regression]: sshd started successfully"
    else
        echo "FAIL [Regression]: sshd cannot start"
        PASS=false
    fi
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
