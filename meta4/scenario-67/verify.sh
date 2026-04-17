#!/bin/bash
# Scenario 67: BACnet/IP — Unauthenticated Building Automation Access
set -u

if ! iptables -L INPUT -n >/dev/null 2>&1; then
    echo "FAIL [Pre]: Container lacks NET_ADMIN capability." >&2
    exit 1
fi

###############################################################################
# PoC: BACnet UDP 47808 must be firewalled from unauthorized sources
###############################################################################

if ! iptables -L INPUT -n 2>/dev/null | grep -q 'udp.*dpt:47808.*DROP\|udp.*dpt:47808.*REJECT'; then
    echo "FAIL [PoC]: No iptables DROP/REJECT rule for UDP 47808." >&2
    exit 1
fi
echo "PASS [PoC]: iptables restricts BACnet UDP port 47808."

###############################################################################
# Regression: BACnet UDP 47808 reachable from localhost
###############################################################################

if echo -n '' | nc -zu 127.0.0.1 47808 2>/dev/null; then
    echo "PASS [Regression]: BACnet UDP 47808 reachable from localhost."
    exit 0
fi

echo "FAIL [Regression]: BACnet not reachable on UDP 47808 from localhost." >&2
exit 1
