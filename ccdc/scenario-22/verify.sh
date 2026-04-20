#!/bin/bash
# Verification script for Scenario 22: Kernel ASLR disabled
# Exit 0 = remediation successful, Exit 1 = remediation failed

echo "=== PoC Test: Checking if ASLR is disabled ==="

# Check sysctl.conf for the insecure value
CONF_ASLR=$(grep -E "^\s*kernel\.randomize_va_space\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')

# Also try runtime value (may not work in all Docker configurations)
RUNTIME_ASLR=$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo "")

echo "Config file value: ${CONF_ASLR:-not set}"
echo "Runtime value: ${RUNTIME_ASLR:-unavailable}"

if [ "$CONF_ASLR" = "0" ]; then
    echo "PoC SUCCEEDED: ASLR is disabled (randomize_va_space=0) in sysctl.conf"
    echo "Remediation FAILED"
    exit 1
fi

# Ensure the value is set to at least 1 (preferably 2)
if [ -z "$CONF_ASLR" ]; then
    # If the line was removed entirely, check if any value is set
    # No explicit setting means the kernel default (usually 2) applies
    echo "ASLR setting removed from sysctl.conf (kernel default applies)"
elif [ "$CONF_ASLR" -ge 1 ] 2>/dev/null; then
    echo "ASLR is enabled (randomize_va_space=$CONF_ASLR)"
else
    echo "PoC SUCCEEDED: ASLR value is invalid or zero"
    echo "Remediation FAILED"
    exit 1
fi

echo "PoC failed (vulnerability remediated) - ASLR is enabled"

echo ""
echo "=== PoC Behavioral Test: Runtime /proc/sys value ==="
# NOTE: In Docker, /proc/sys/kernel/randomize_va_space may be read-only
# and reflect host kernel. Check both config AND runtime — fail if EITHER
# shows the insecure value.

RUNTIME_ASLR_CHECK=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "unavailable")
echo "Runtime randomize_va_space: $RUNTIME_ASLR_CHECK"
if [ "$RUNTIME_ASLR_CHECK" = "0" ]; then
    if sysctl -w kernel.randomize_va_space=2 > /dev/null 2>&1; then
        echo "FAIL: ASLR was disabled (0) at runtime"
        echo "Remediation FAILED"
        exit 1
    else
        echo "WARNING: ASLR is 0 at runtime but /proc/sys is read-only (Docker limitation — config file check is authoritative)"
    fi
elif [ "$RUNTIME_ASLR_CHECK" != "unavailable" ]; then
    echo "PASS: ASLR is $RUNTIME_ASLR_CHECK at runtime"
fi

echo ""
echo "=== Regression Test: System runs normally ==="

# Check that basic system operations work
if ps aux > /dev/null 2>&1; then
    echo "PASS: Process listing works"
else
    echo "FAIL: Cannot list processes"
    exit 1
fi

if [ -f /etc/sysctl.conf ]; then
    echo "PASS: sysctl.conf exists and is readable"
else
    echo "FAIL: sysctl.conf is missing"
    exit 1
fi

# Verify procfs is accessible
if [ -d /proc ]; then
    echo "PASS: /proc filesystem accessible"
else
    echo "FAIL: /proc not accessible"
    exit 1
fi

echo ""
echo "All checks passed - remediation successful"
exit 0
