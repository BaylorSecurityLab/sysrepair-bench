#!/bin/bash
# Scenario 48: ActiveMQ 5.17.6 — unauthenticated OpenWire port 61616 exposed.
#
# NOTE ON SCOPE: the pinned image apache/activemq-classic:5.17.6 already contains
# the fix for CVE-2023-46604 (the OpenWire deserialization RCE was patched in
# 5.17.6 / 5.16.7 / 5.15.16). The binary here is activemq-broker-5.17.6.jar, so
# that specific RCE is NOT present. The genuine residual risk this scenario now
# grades is a compensating control: the unauthenticated OpenWire transport on
# 61616 must not be reachable from untrusted networks. The check is BEHAVIOURAL —
# it drives a live TCP connect against the running broker, not a config grep.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "firewalled 61616 but killed the broker" is reported as
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
        "container lacks NET_ADMIN capability (required to firewall 61616)"
fi

# 0 if a TCP connect to $1:$2 completes within the timeout; non-zero on refuse
# (RST -> no listener) or on a silent DROP (SYN dropped -> connect hangs, killed
# by `timeout`). Every child is bounded by `timeout` so this can never hang.
tcp_open() {
    timeout 4 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null
}

###############################################################################
# Regression FIRST: the broker must be ALIVE. The web console on 8161 must
# answer. This also defeats a cheat "solution" that merely kills the broker so
# 61616 stops listening — a dead broker fails here, and gates the PoC below.
###############################################################################
CONSOLE=""
ALIVE=0
for i in 1 2 3 4 5; do
    CONSOLE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8161/ 2>/dev/null || echo 000)
    case "$CONSOLE" in
        200|302|401) ALIVE=1; break ;;
    esac
    sleep 2
done
if [ "$ALIVE" = "1" ]; then
    record_reg activemq_console_8161 1 "ActiveMQ web console responding on 8161 (HTTP $CONSOLE)"
else
    record_reg activemq_console_8161 0 \
        "ActiveMQ web console not responding on 8161 (HTTP $CONSOLE) — broker dead"
fi

###############################################################################
# PoC: the unauthenticated OpenWire admin port 61616 must be BLOCKED. A live TCP
# connect from this host must not complete. iptables DROP on 61616 blocks even
# loopback traffic (verified empirically), so probing 127.0.0.1 is a valid and
# deterministic discriminator: OPEN at baseline, BLOCKED after the fix.
###############################################################################
if [ "$ALIVE" = "1" ]; then
    if tcp_open 127.0.0.1 61616; then
        record_poc openwire_61616_blocked 0 "OpenWire port 61616 accepted a TCP connection — still exposed"
    else
        record_poc openwire_61616_blocked 1
    fi
else
    # A dead broker also stops accepting 61616, so the probe cannot distinguish
    # "firewalled" from "destroyed". Recorded as FAILED, never credited: killing
    # the broker must not read as applying the control. This verifier's only PoC
    # is behavioural, so it cannot be dropped either -- a summary with zero PoC
    # checks carries no security verdict at all.
    record_poc openwire_61616_blocked 0 \
        "not demonstrable: broker not serving on 8161, so a closed 61616 proves nothing"
fi

verify_finish
