#!/bin/bash
# Scenario 66: IPMI — Cipher-Zero Auth Bypass
set -u

if ! iptables -L INPUT -n >/dev/null 2>&1; then
    echo "FAIL [Pre]: Container lacks NET_ADMIN capability." >&2
    exit 1
fi

###############################################################################
# PoC 1: UDP 623 must be firewalled from unauthorized sources
###############################################################################

if ! iptables -L INPUT -n 2>/dev/null | grep -q 'udp.*dpt:623.*DROP\|udp.*dpt:623.*REJECT'; then
    echo "FAIL [PoC]: No iptables DROP/REJECT rule for UDP 623." >&2
    exit 1
fi
echo "PASS [PoC]: iptables restricts UDP port 623."

###############################################################################
# PoC 2: Cipher 0 must be disabled in config
###############################################################################

if grep -q 'cipher_suite_ids\s*=\s*[^#]*\b0\b' /etc/ipmi.conf 2>/dev/null; then
    echo "FAIL [PoC]: Cipher 0 still listed in /etc/ipmi.conf." >&2
    exit 1
fi
echo "PASS [PoC]: Cipher 0 is disabled in IPMI config."

###############################################################################
# Regression: IPMI UDP 623 reachable from localhost
###############################################################################

if echo -n '' | nc -zu 127.0.0.1 623 2>/dev/null; then
    echo "PASS [Regression]: IPMI UDP 623 reachable from localhost."
    exit 0
fi

echo "FAIL [Regression]: IPMI not reachable on UDP 623 from localhost." >&2
exit 1
