#!/bin/bash
# Verification script for Scenario 02: SSH Weak Host Key Algorithms
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

SSHD_CONFIG="/etc/ssh/sshd_config"

###############################################################################
# PoC Check 1: ssh-dss / DSA host key must be removed from config and disk
###############################################################################

if grep -qi 'HostKey[[:space:]]*/etc/ssh/ssh_host_dsa_key' "$SSHD_CONFIG"; then
    echo "FAIL [PoC]: DSA HostKey is still referenced in sshd_config." >&2
    exit 1
fi

if [ -f /etc/ssh/ssh_host_dsa_key ]; then
    echo "FAIL [PoC]: DSA host key file /etc/ssh/ssh_host_dsa_key still exists on disk." >&2
    exit 1
fi

echo "PASS [PoC]: DSA host key removed from config and disk."

###############################################################################
# PoC Check 2: HostKeyAlgorithms must not include ssh-rsa or ssh-dss
###############################################################################

if grep -qi '^HostKeyAlgorithms' "$SSHD_CONFIG"; then
    HKA_LINE=$(grep -i '^HostKeyAlgorithms' "$SSHD_CONFIG" | tail -1 | \
               sed 's/^[Hh]ost[Kk]ey[Aa]lgorithms[[:space:]]*//')
    for weak_alg in ssh-rsa ssh-dss; do
        if echo "$HKA_LINE" | grep -qi "$weak_alg"; then
            echo "FAIL [PoC]: Weak host key algorithm '$weak_alg' is still listed in HostKeyAlgorithms." >&2
            exit 1
        fi
    done
    echo "PASS [PoC]: HostKeyAlgorithms does not include ssh-rsa or ssh-dss."
else
    # No directive means the OpenSSH default applies; on older versions that default
    # includes ssh-rsa. Require an explicit directive to be safe.
    echo "FAIL [PoC]: No HostKeyAlgorithms directive found — implicit defaults may include ssh-rsa." >&2
    exit 1
fi

###############################################################################
# PoC Check 3: Connection using ssh-dss must be rejected
###############################################################################

if ssh -o BatchMode=yes \
       -o StrictHostKeyChecking=no \
       -o ConnectTimeout=5 \
       -o HostKeyAlgorithms=ssh-dss \
       -p 22 localhost true 2>/dev/null; then
    echo "FAIL [PoC]: sshd still accepted an ssh-dss host key connection." >&2
    exit 1
fi

echo "PASS [PoC]: sshd rejected ssh-dss host key algorithm as expected."

###############################################################################
# Regression Check: Connection using rsa-sha2-256 must succeed
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
