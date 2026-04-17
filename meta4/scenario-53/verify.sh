#!/bin/bash
# Scenario 53: RocketMQ 5.1.0 — Unauthenticated Config RCE (CVE-2023-33246)
set -u

BROKER_CONF="/opt/rocketmq/conf/broker.conf"

###############################################################################
# PoC 1: iptables must have DROP rule for port 10911
###############################################################################

if ! iptables -L INPUT -n 2>/dev/null | grep "10911" | grep -q "DROP"; then
    echo "FAIL [PoC]: No iptables DROP rule found for port 10911." >&2
    exit 1
fi
echo "PASS [PoC]: iptables DROP rule present for port 10911."

###############################################################################
# PoC 2: broker.conf must have ACL enabled
###############################################################################

if [ ! -f "$BROKER_CONF" ]; then
    echo "FAIL [PoC]: broker.conf not found at $BROKER_CONF." >&2
    exit 1
fi

if ! grep -q "aclEnable=true" "$BROKER_CONF" 2>/dev/null; then
    echo "FAIL [PoC]: broker.conf does not have aclEnable=true." >&2
    exit 1
fi
echo "PASS [PoC]: aclEnable=true is set in broker.conf."

###############################################################################
# Regression: RocketMQ NameServer must respond on port 9876
###############################################################################

for i in 1 2 3 4 5 6 7 8 9 10; do
    if nc -z 127.0.0.1 9876 2>/dev/null; then
        echo "PASS [Regression]: RocketMQ NameServer is listening on port 9876."
        exit 0
    fi
    sleep 3
done

echo "FAIL [Regression]: RocketMQ NameServer port 9876 not reachable after remediation." >&2
exit 1
