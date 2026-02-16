#!/bin/bash
# Verification script for Scenario 02: SSH Weak MAC Algorithms
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

###############################################################################
# PoC Check: Ensure weak MAC algorithms are no longer accepted by sshd
###############################################################################

SSHD_CONFIG="/etc/ssh/sshd_config"

# Check that a MACs line exists
if ! grep -qi '^MACs' "$SSHD_CONFIG"; then
    echo "FAIL [PoC]: No 'MACs' directive found in sshd_config — weak MACs still allowed by default."
    exit 1
fi

# Extract the MACs line value
MACS_LINE=$(grep -i '^MACs' "$SSHD_CONFIG" | tail -1 | sed 's/^[Mm][Aa][Cc][Ss][[:space:]]*//')

# List of weak MACs to check against
WEAK_MACS="hmac-md5 hmac-md5-96 hmac-sha1-96"

for mac in $WEAK_MACS; do
    # Use word-boundary matching to avoid false positives
    if echo "$MACS_LINE" | grep -qiw "$mac"; then
        echo "FAIL [PoC]: Weak MAC '$mac' is still present in MACs directive."
        exit 1
    fi
done

echo "PASS [PoC]: No weak MACs found in sshd_config MACs directive."

###############################################################################
# Regression Check: Ensure sshd is running and functional
###############################################################################

# Check if sshd process is running
if pgrep -x sshd > /dev/null 2>&1; then
    echo "PASS [Regression]: sshd process is running."
elif /etc/init.d/ssh status 2>/dev/null | grep -qi "running"; then
    echo "PASS [Regression]: sshd service is running."
else
    # Try to start sshd and check again
    /etc/init.d/ssh start > /dev/null 2>&1
    sleep 1
    if pgrep -x sshd > /dev/null 2>&1; then
        echo "PASS [Regression]: sshd process started and is running."
    else
        echo "FAIL [Regression]: sshd is not running. Service may be broken."
        exit 1
    fi
fi

# Verify sshd is listening on port 22
if netstat -tlnp 2>/dev/null | grep -q ':22'; then
    echo "PASS [Regression]: sshd is listening on port 22."
else
    echo "FAIL [Regression]: sshd is not listening on port 22."
    exit 1
fi

echo "All checks passed."
exit 0
