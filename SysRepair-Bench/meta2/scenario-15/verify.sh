#!/bin/bash
# Verification script for Scenario 15: DistCC Unrestricted Access (RCE)
# Check 1 (PoC): distccd should NOT accept remote commands without restriction
# Check 2 (Regression): distcc should be properly restricted or stopped

##############################################################################
# PoC Check: distccd should not be running unrestricted
##############################################################################

DISTCC_PID=$(pgrep -f 'distccd' 2>/dev/null)

if [ -n "$DISTCC_PID" ]; then
    # distccd is running -- check if it has --allow restriction
    DISTCC_CMDLINE=$(cat /proc/$DISTCC_PID/cmdline 2>/dev/null | tr '\0' ' ')

    if echo "$DISTCC_CMDLINE" | grep -q '\-\-allow'; then
        # Has --allow flag -- check it is not wide open (e.g., 0.0.0.0/0)
        if echo "$DISTCC_CMDLINE" | grep -qE '\-\-allow\s+0\.0\.0\.0/0'; then
            echo "FAIL: distccd has --allow 0.0.0.0/0 which allows all hosts."
            exit 1
        else
            echo "PASS: distccd is running with --allow restriction."
        fi
    else
        echo "FAIL: distccd is running without --allow flag -- unrestricted access."
        exit 1
    fi
else
    echo "PASS: distccd is not running (service disabled)."
fi

##############################################################################
# Additional PoC: Try to connect and execute a command via distcc protocol
##############################################################################

if [ -n "$DISTCC_PID" ]; then
    # Attempt a basic distcc protocol command execution
    # The distcc protocol sends DIST followed by argument count and arguments
    # A simple test: try to connect to port 3632 from localhost
    CONNECT_TEST=$(echo "" | nc -w 3 127.0.0.1 3632 2>/dev/null; echo $?)

    if [ "$CONNECT_TEST" = "0" ] || netstat -tlnp 2>/dev/null | grep -q ':3632.*0.0.0.0'; then
        # Port is open -- check if bound to 0.0.0.0 (all interfaces)
        LISTEN_ADDR=$(netstat -tlnp 2>/dev/null | grep ':3632' | awk '{print $4}')
        if echo "$LISTEN_ADDR" | grep -q '0.0.0.0:3632'; then
            # Still listening on all interfaces, but we already checked --allow above
            # If --allow is set, this is acceptable (the flag controls access)
            echo "INFO: distccd listening on all interfaces but access is controlled via --allow."
        fi
    fi
fi

##############################################################################
# Regression Check: If distcc is running, it should be properly restricted
# If stopped, that is also an acceptable remediation
##############################################################################

if [ -n "$DISTCC_PID" ]; then
    # distcc is running -- verify it responds on localhost (for legitimate local use)
    if netstat -tlnp 2>/dev/null | grep -q ':3632'; then
        echo "PASS: distccd is running and listening (restricted mode)."
    else
        echo "FAIL: distccd process exists but is not listening on port 3632."
        exit 1
    fi
else
    # distcc is stopped -- this is acceptable, verify the system is otherwise functional
    echo "PASS: distccd is stopped -- service has been disabled as remediation."
fi

echo "All checks passed."
exit 0
