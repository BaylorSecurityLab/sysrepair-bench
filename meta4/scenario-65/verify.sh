#!/bin/bash
# Scenario 65: S7comm — Unauthenticated PLC Access
set -u

if ! iptables -L INPUT -n >/dev/null 2>&1; then
    echo "FAIL [Pre]: Container lacks NET_ADMIN capability." >&2
    exit 1
fi

###############################################################################
# PoC: S7comm port must not be accessible from unauthorized sources
###############################################################################

if ss -tlnp | grep ':102' | grep -q '0.0.0.0'; then
    if ! iptables -L INPUT -n 2>/dev/null | grep -q 'dpt:102.*DROP\|dpt:102.*REJECT'; then
        echo "FAIL [PoC]: S7comm on 0.0.0.0:102 with no firewall restriction." >&2
        exit 1
    fi
fi
echo "PASS [PoC]: S7comm port 102 is restricted."

###############################################################################
# Regression: S7comm must still accept connections from localhost
###############################################################################

if nc -z 127.0.0.1 102 2>/dev/null; then
    echo "PASS [Regression]: S7comm responds on localhost."
    exit 0
fi

echo "FAIL [Regression]: S7comm not responding on localhost." >&2
exit 1
