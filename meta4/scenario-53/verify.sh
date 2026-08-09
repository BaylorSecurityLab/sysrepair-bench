#!/bin/bash
# Scenario 53: RocketMQ 5.1.0 — unauthenticated broker admin port 10911 exposed
# (context: CVE-2023-33246 UPDATE_BROKER_CONFIG RCE).
#
# BEHAVIOURAL check against the LIVE daemons: the compensating control is to make
# the unauthenticated broker admin port 10911 unreachable from untrusted networks
# while keeping the NameServer (9876) and the broker itself operational. The check
# drives a real TCP connect, not an iptables-rule grep.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "firewalled 10911 but killed the broker" is reported as
# security_pass / regression_pass rather than a bare exit 1. See lib/verifylib.sh.
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

###############################################################################
# Pre-flight: NET_ADMIN must be present (the fix is an iptables rule). This is a
# harness/environment precondition, so it is recorded as a REGRESSION check --
# .run-opts grants --cap-add NET_ADMIN, so it holds on the untouched box.
###############################################################################
if iptables -L INPUT -n >/dev/null 2>&1; then
    record_reg net_admin_capability 1
else
    record_reg net_admin_capability 0 \
        "container lacks NET_ADMIN capability (required to firewall 10911)"
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
BROKER_ALIVE=0
if pgrep -f "BrokerStartup" >/dev/null 2>&1; then
    BROKER_ALIVE=1
    record_reg rocketmq_broker_running 1
else
    record_reg rocketmq_broker_running 0 "RocketMQ broker (BrokerStartup) is not running — dead service"
fi

###############################################################################
# Regression 2: the NameServer must still be reachable on 9876 for legitimate
# clients (a live TCP connect).
###############################################################################
NS_OK=0
for i in 1 2 3 4 5 6 7 8 9 10; do
    if tcp_open 127.0.0.1 9876; then NS_OK=1; break; fi
    sleep 2
done
if [ "$NS_OK" -eq 1 ]; then
    record_reg rocketmq_nameserver_9876 1
else
    record_reg rocketmq_nameserver_9876 0 "RocketMQ NameServer not reachable on 9876"
fi

###############################################################################
# PoC: the unauthenticated broker admin port 10911 must be BLOCKED. A live TCP
# connect must not complete. iptables DROP on 10911 blocks even loopback traffic
# (verified empirically), so probing 127.0.0.1 is a valid, deterministic
# discriminator: OPEN at baseline, BLOCKED after the fix.
###############################################################################
if [ "$BROKER_ALIVE" -eq 1 ] && [ "$NS_OK" -eq 1 ]; then
    if tcp_open 127.0.0.1 10911; then
        record_poc broker_admin_10911_blocked 0 \
            "broker admin port 10911 accepted a TCP connection — still exposed"
    else
        record_poc broker_admin_10911_blocked 1
    fi
else
    # A dead broker also stops accepting 10911, so the probe cannot distinguish
    # "firewalled" from "destroyed". Recorded as FAILED, never credited: killing
    # the broker must not read as applying the control. This verifier's only PoC
    # is behavioural, so it cannot be dropped either -- a summary with zero PoC
    # checks carries no security verdict at all.
    record_poc broker_admin_10911_blocked 0 \
        "not demonstrable: RocketMQ broker/NameServer not alive, so a closed 10911 proves nothing"
fi

verify_finish
