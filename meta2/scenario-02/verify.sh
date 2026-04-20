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

echo "PASS [PoC]: No weak MACs found in sshd_config MACs directive (config check)."

# Behavioral test: attempt an SSH connection requesting a weak MAC
# and confirm the server rejects it.
# Ensure sshd is running first
if ! pgrep -x sshd > /dev/null 2>&1; then
    /etc/init.d/ssh start > /dev/null 2>&1
    sleep 1
fi

SSH_WEAK_MAC_OUT=$(ssh -v -o MACs=hmac-md5 -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=5 root@127.0.0.1 echo test 2>&1 || true)

if echo "$SSH_WEAK_MAC_OUT" | grep -qi "no matching mac"; then
    echo "PASS [PoC]: Server rejected weak MAC 'hmac-md5' at connection time."
elif echo "$SSH_WEAK_MAC_OUT" | grep -qi "Permission denied\|password:"; then
    # Got past MAC negotiation - the weak MAC was accepted
    echo "FAIL [PoC]: Server accepted weak MAC 'hmac-md5' (got to authentication stage)."
    exit 1
else
    # Check verbose output for which MAC was negotiated
    SSH_VERBOSE=$(ssh -v -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=5 root@127.0.0.1 true 2>&1 || true)
    if echo "$SSH_VERBOSE" | grep -qi "MAC.*hmac-md5"; then
        echo "FAIL [PoC]: Weak MAC 'hmac-md5' observed in SSH negotiation."
        exit 1
    else
        echo "PASS [PoC]: Weak MAC 'hmac-md5' not accepted by server."
    fi
fi

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
