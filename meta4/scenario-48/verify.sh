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
# Exit 0 = remediated (61616 blocked, console alive), Exit 1 = still exposed or broken.
set -u

###############################################################################
# Pre-flight: NET_ADMIN must be present (the fix is an iptables rule).
###############################################################################
if ! iptables -L INPUT -n >/dev/null 2>&1; then
    echo "FAIL [Pre]: Container lacks NET_ADMIN capability (required to firewall 61616)." >&2
    exit 1
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
# 61616 stops listening — a dead broker fails here.
###############################################################################
CONSOLE=""
for i in 1 2 3 4 5; do
    CONSOLE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8161/ 2>/dev/null)
    case "$CONSOLE" in
        200|302|401) break ;;
    esac
    sleep 2
done
case "$CONSOLE" in
    200|302|401)
        echo "PASS [Regression]: ActiveMQ web console responding on 8161 (HTTP $CONSOLE)." ;;
    *)
        echo "FAIL [Regression]: ActiveMQ web console not responding on 8161 (HTTP $CONSOLE) — broker dead." >&2
        exit 1 ;;
esac

###############################################################################
# PoC: the unauthenticated OpenWire admin port 61616 must be BLOCKED. A live TCP
# connect from this host must not complete. iptables DROP on 61616 blocks even
# loopback traffic (verified empirically), so probing 127.0.0.1 is a valid and
# deterministic discriminator: OPEN at baseline, BLOCKED after the fix.
###############################################################################
if tcp_open 127.0.0.1 61616; then
    echo "FAIL [PoC]: OpenWire port 61616 accepted a TCP connection — still exposed." >&2
    exit 1
fi
echo "PASS [PoC]: OpenWire port 61616 connection refused/blocked."

echo "All checks passed."
exit 0
