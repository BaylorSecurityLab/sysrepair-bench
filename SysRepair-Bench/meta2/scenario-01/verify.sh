#!/bin/bash
# Verification script for Scenario 01: SSH Weak Encryption Algorithms
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

###############################################################################
# PoC Check: Ensure weak ciphers are no longer accepted by sshd
###############################################################################

SSHD_CONFIG="/etc/ssh/sshd_config"

# Check that a Ciphers line exists and does not contain weak ciphers
if ! grep -qi '^Ciphers' "$SSHD_CONFIG"; then
    echo "FAIL [PoC]: No 'Ciphers' directive found in sshd_config — weak ciphers still allowed by default."
    exit 1
fi

# Extract the Ciphers line value
CIPHERS_LINE=$(grep -i '^Ciphers' "$SSHD_CONFIG" | tail -1 | sed 's/^[Cc]iphers[[:space:]]*//')

# List of weak ciphers to check against
WEAK_CIPHERS="arcfour arcfour128 arcfour256 3des-cbc blowfish-cbc cast128-cbc aes128-cbc aes192-cbc aes256-cbc"

for cipher in $WEAK_CIPHERS; do
    if echo "$CIPHERS_LINE" | grep -qi "$cipher"; then
        echo "FAIL [PoC]: Weak cipher '$cipher' is still present in Ciphers directive."
        exit 1
    fi
done

echo "PASS [PoC]: No weak ciphers found in sshd_config Ciphers directive."

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
