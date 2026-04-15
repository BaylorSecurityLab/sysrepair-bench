#!/bin/bash
# Verification script for Scenario 01: SSH Weak KEX Algorithms
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

SSHD_CONFIG="/etc/ssh/sshd_config"

###############################################################################
# PoC Check: Ensure weak SHA1-based KEX algorithms are no longer present
###############################################################################

if ! grep -qi '^KexAlgorithms' "$SSHD_CONFIG"; then
    echo "FAIL [PoC]: No KexAlgorithms directive found in sshd_config — weak KEX still allowed by default." >&2
    exit 1
fi

KEX_LINE=$(grep -i '^KexAlgorithms' "$SSHD_CONFIG" | tail -1 | sed 's/^[Kk]ex[Aa]lgorithms[[:space:]]*//')

WEAK_KEX="diffie-hellman-group1-sha1 diffie-hellman-group14-sha1 diffie-hellman-group-exchange-sha1"

for kex in $WEAK_KEX; do
    if echo "$KEX_LINE" | grep -qi "$kex"; then
        echo "FAIL [PoC]: Weak KEX algorithm '$kex' is still present in KexAlgorithms directive." >&2
        exit 1
    fi
done

echo "PASS [PoC]: No weak SHA1-based KEX algorithms found in sshd_config."

# Attempt connection with a weak KEX algorithm — must be rejected
# (ssh exits non-zero when no common KEX can be negotiated)
if ssh -o BatchMode=yes \
       -o StrictHostKeyChecking=no \
       -o ConnectTimeout=5 \
       -o KexAlgorithms=diffie-hellman-group1-sha1 \
       -p 22 localhost true 2>/dev/null; then
    echo "FAIL [PoC]: sshd still accepted diffie-hellman-group1-sha1 KEX." >&2
    exit 1
fi

echo "PASS [PoC]: sshd rejected diffie-hellman-group1-sha1 KEX connection as expected."

###############################################################################
# Regression Check: Ensure sshd is running and reachable on port 22
###############################################################################

if ! pgrep -x sshd > /dev/null 2>&1; then
    /etc/init.d/ssh start > /dev/null 2>&1
    sleep 1
    if ! pgrep -x sshd > /dev/null 2>&1; then
        echo "FAIL [Regression]: sshd is not running after attempted restart." >&2
        exit 1
    fi
fi

if ! netstat -tlnp 2>/dev/null | grep -q ':22 '; then
    echo "FAIL [Regression]: sshd is not listening on port 22." >&2
    exit 1
fi

echo "PASS [Regression]: sshd is running and listening on port 22."

echo "All checks passed."
exit 0
