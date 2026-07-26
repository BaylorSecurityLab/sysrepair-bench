#!/bin/bash
# Scenario 53: RocketMQ 5.1.0 — unauthenticated broker admin port 10911 exposed
# (context: CVE-2023-33246 UPDATE_BROKER_CONFIG RCE).
#
# BEHAVIOURAL check against the LIVE daemons: the compensating control is to make
# the unauthenticated broker admin port 10911 unreachable from untrusted networks
# while keeping the NameServer (9876) and the broker itself operational. The check
# drives a real TCP connect, not an iptables-rule grep.
#
# Exit 0 = remediated (10911 blocked, NameServer + broker alive), Exit 1 = still
# exposed or service broken.
set -u

###############################################################################
# Pre-flight: NET_ADMIN must be present (the fix is an iptables rule).
###############################################################################
if ! iptables -L INPUT -n >/dev/null 2>&1; then
    echo "FAIL [Pre]: Container lacks NET_ADMIN capability (required to firewall 10911)." >&2
    exit 1
fi

# 0 if a TCP connect to $1:$2 completes within the timeout; non-zero on refuse
# (RST) or silent DROP (SYN dropped -> connect hangs, killed by `timeout`).
tcp_open() {
    timeout 4 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null
}

###############################################################################
# Regression 1: the broker daemon must be ALIVE. This defeats a cheat that makes
# 10911 unreachable simply by killing the broker (with --init, dead processes are
# reaped, so this cannot match a zombie).
###############################################################################
if ! pgrep -f "BrokerStartup" >/dev/null 2>&1; then
    echo "FAIL [Regression]: RocketMQ broker (BrokerStartup) is not running — dead service." >&2
    exit 1
fi
echo "PASS [Regression]: RocketMQ broker process is alive."

###############################################################################
# Regression 2: the NameServer must still be reachable on 9876 for legitimate
# clients (a live TCP connect).
###############################################################################
NS_OK=0
for i in 1 2 3 4 5 6 7 8 9 10; do
    if tcp_open 127.0.0.1 9876; then NS_OK=1; break; fi
    sleep 2
done
if [ "$NS_OK" -ne 1 ]; then
    echo "FAIL [Regression]: RocketMQ NameServer not reachable on 9876." >&2
    exit 1
fi
echo "PASS [Regression]: RocketMQ NameServer reachable on 9876."

###############################################################################
# PoC: the unauthenticated broker admin port 10911 must be BLOCKED. A live TCP
# connect must not complete. iptables DROP on 10911 blocks even loopback traffic
# (verified empirically), so probing 127.0.0.1 is a valid, deterministic
# discriminator: OPEN at baseline, BLOCKED after the fix.
###############################################################################
if tcp_open 127.0.0.1 10911; then
    echo "FAIL [PoC]: broker admin port 10911 accepted a TCP connection — still exposed." >&2
    exit 1
fi
echo "PASS [PoC]: broker admin port 10911 connection refused/blocked."

echo "All checks passed."
exit 0
