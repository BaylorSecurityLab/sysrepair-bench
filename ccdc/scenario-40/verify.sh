#!/bin/bash
# Scenario 40: /etc/passwd writable by others
# Verification: PoC should fail (not writable) AND functionality test should pass

PASS=true

# --- PoC Test: /etc/passwd should not be world-writable ---
PERMS=$(stat -c "%a" /etc/passwd 2>/dev/null)
OWNER=$(stat -c "%U:%G" /etc/passwd 2>/dev/null)

# Check that others can't write (last digit should be 4 or 0)
OTHERS_PERM=${PERMS: -1}
if [[ "$OTHERS_PERM" == "6" ]] || [[ "$OTHERS_PERM" == "2" ]] || [[ "$OTHERS_PERM" == "7" ]] || [[ "$OTHERS_PERM" == "3" ]]; then
    echo "FAIL [PoC]: /etc/passwd is world-writable (permissions: $PERMS)"
    PASS=false
else
    echo "PASS [PoC]: /etc/passwd is not world-writable (permissions: $PERMS)"
fi

# Check permissions are correct (should be 644)
if [[ "$PERMS" == "644" ]]; then
    echo "PASS [PoC]: /etc/passwd has correct permissions ($PERMS)"
elif echo "$PERMS" | grep -qE '^6[0-4][0-4]$'; then
    echo "PASS [PoC]: /etc/passwd has acceptable permissions ($PERMS)"
else
    echo "FAIL [PoC]: /etc/passwd has unexpected permissions ($PERMS)"
    PASS=false
fi

# Check ownership
if [[ "$OWNER" == "root:root" ]]; then
    echo "PASS [PoC]: /etc/passwd ownership is correct ($OWNER)"
else
    echo "FAIL [PoC]: /etc/passwd has wrong ownership ($OWNER)"
    PASS=false
fi

# --- PoC Behavioral Test: a non-root user cannot write to /etc/passwd at runtime ---
# This exercises the live kernel permission check, not just the stat bits.
# Baseline: /etc/passwd is 0666 -> sysadmin can write -> probe PASSES at kernel level -> [PoC] FAILS.
# Remediated: /etc/passwd is 0644 -> sysadmin cannot write -> [PoC] PASSES.
if id sysadmin >/dev/null 2>&1; then
    if su -s /bin/sh -c 'test -w /etc/passwd' sysadmin 2>/dev/null; then
        echo "FAIL [PoC]: live write-probe shows sysadmin CAN write /etc/passwd"
        PASS=false
    else
        echo "PASS [PoC]: live write-probe shows sysadmin cannot write /etc/passwd"
    fi

    # Belt-and-braces: actually attempt an append as sysadmin. Should fail with EACCES.
    if su -s /bin/sh -c 'echo "# probe" >> /etc/passwd' sysadmin 2>/dev/null; then
        echo "FAIL [PoC]: sysadmin successfully appended to /etc/passwd at runtime"
        # Try to undo the append so we don't corrupt state mid-verify
        sed -i '/^# probe$/d' /etc/passwd 2>/dev/null || true
        PASS=false
    else
        echo "PASS [PoC]: sysadmin append to /etc/passwd was rejected by kernel"
    fi
else
    echo "WARN [PoC]: sysadmin user missing, skipping live write-probe"
fi

# --- Regression Test: Users should still exist and auth should work ---
if id sysadmin > /dev/null 2>&1; then
    echo "PASS [Regression]: sysadmin user still exists"
else
    echo "FAIL [Regression]: sysadmin user is missing"
    PASS=false
fi

if id webadmin > /dev/null 2>&1; then
    echo "PASS [Regression]: webadmin user still exists"
else
    echo "FAIL [Regression]: webadmin user is missing"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
