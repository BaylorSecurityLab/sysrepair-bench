#!/bin/bash
# Scenario 39: Ubuntu 8.04 EOL — compensating control (default-deny host firewall)
# PoC  : iptables INPUT policy must be DROP, with explicit ACCEPT for SSH/22 only
# Reg. : sshd still running and listening on 22

set -u

IPT=$(iptables-save 2>/dev/null || true)
if [ -z "$IPT" ]; then
    echo "FAIL [PoC]: iptables not usable (container needs --cap-add=NET_ADMIN)."
    exit 1
fi

if ! echo "$IPT" | grep -qE '(^-P INPUT DROP|^:INPUT DROP)'; then
    echo "FAIL [PoC]: INPUT policy is not DROP."
    echo "$IPT"
    exit 1
fi
echo "PASS [PoC]: INPUT policy is DROP."

if ! echo "$IPT" | grep -qE -- '-A INPUT.*(--dport 22|dports .*22).*-j ACCEPT'; then
    echo "FAIL [PoC]: no explicit ACCEPT rule for port 22."
    exit 1
fi
echo "PASS [PoC]: SSH accept rule present."

if ! pgrep -x sshd > /dev/null 2>&1; then
    /usr/sbin/sshd > /dev/null 2>&1
    sleep 1
fi
if ! pgrep -x sshd > /dev/null 2>&1; then
    echo "FAIL [Regression]: sshd not running."
    exit 1
fi
if ! netstat -tlnp 2>/dev/null | grep -q ':22'; then
    echo "FAIL [Regression]: sshd not listening on 22."
    exit 1
fi
echo "PASS [Regression]: sshd reachable on 22."

echo "All checks passed."
exit 0
