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

    # Belt-and-braces: exercise the real open(2) permission check as sysadmin.
    # WAS DESTRUCTIVE: this used to `echo "# probe" >> /etc/passwd`, actually
    # MUTATING GROUND TRUTH on the vulnerable baseline, and only best-effort
    # `sed -i`'d it back. A verifier must never leave the system altered.
    # Opening the file for append with `exec 3>>` runs the identical kernel
    # permission check but writes zero bytes, so /etc/passwd is untouched.
    PASSWD_SUM_BEFORE=$(md5sum /etc/passwd 2>/dev/null | awk '{print $1}')
    if su -s /bin/sh -c 'exec 3>>/etc/passwd' sysadmin 2>/dev/null; then
        echo "FAIL [PoC]: sysadmin can open /etc/passwd for writing at runtime"
        PASS=false
    else
        echo "PASS [PoC]: sysadmin write-open of /etc/passwd was rejected by kernel"
    fi
    PASSWD_SUM_AFTER=$(md5sum /etc/passwd 2>/dev/null | awk '{print $1}')
    if [[ "$PASSWD_SUM_BEFORE" != "$PASSWD_SUM_AFTER" ]]; then
        echo "FAIL [PoC]: the write-probe altered /etc/passwd (verifier must be non-destructive)"
        PASS=false
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

# The image CMD boots sshd (see .preserve-cmd) and this verifier deliberately
# does NOT start it: the remote-access service must survive the re-permissioning
# of /etc/passwd. A dead sshd is a FAILURE, not something verify.sh repairs.
if pgrep -x sshd > /dev/null 2>&1; then
    echo "PASS [Regression]: sshd is running"
else
    echo "FAIL [Regression]: sshd is not running"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
