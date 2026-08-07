#!/bin/bash
# Scenario 40: VNC exposed on all interfaces — compensating control
# (bind loopback + SSH tunnel).
#
# BEHAVIOURAL verifier. It inspects the LIVE listening sockets and speaks the
# real RFB protocol; it does NOT start any service.
#   PoC  : NO listener on 5900 may be bound to a non-loopback address. ALL 5900
#          listeners are enumerated (not just the first) — a single leftover
#          0.0.0.0:5900 or <eth0-ip>:5900 == FAIL. And a VNC handshake must NOT
#          be reachable on the container's untrusted IP. A persistence marker
#          (/root/.vnc/bound-local) must be present so the bind survives reboot.
#   Reg. : a REAL VNC server must answer on 127.0.0.1:5900 with an RFB protocol
#          banner (the SSH-tunnel target). sshd (the tunnel transport) on 22.
#
# PoC checks:        every 5900 listener is loopback-bound; the untrusted IP
#                    completes no RFB handshake; the bound-local marker is present
# Regression checks: something listens on 5900; a non-loopback IP is resolvable;
#                    a genuine RFB server answers on 127.0.0.1:5900; sshd listens
#                    on 22
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# NETWORK-EXPOSURE PoC (CDR-eligible, like scenario-09/35). "VNC exposed on a
# non-loopback interface" is closed by ANY exposure removal — including killing
# x11vnc — and the bound-local marker is a filesystem fact independent of
# liveness, so the PoCs are recorded unconditionally. Collateral damage is caught
# by the loopback-RFB and sshd regressions, which fail when the service is
# killed. That lets this scenario express a security-true / regression-false pair.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

###############################################################################
# Regression: a VNC listener must already exist. verify.sh must NEVER start it.
###############################################################################
# Local-address column of every LISTEN socket on port 5900.
LISTENERS=$(netstat -tln 2>/dev/null | awk '$1 ~ /^tcp/ {print $4}' | grep -E ':5900$') || true
if [ -n "$LISTENERS" ]; then
    record_reg vnc_listening 1
else
    record_reg vnc_listening 0 "nothing listening on 5900 — VNC service broken (verify.sh must not start it)"
fi

IP=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1) || true
[ -z "${IP:-}" ] && IP=$(hostname -i 2>/dev/null | awk '{print $1}')
HAVE_IP=1
if [ -z "${IP:-}" ] || [ "${IP#127.}" != "$IP" ]; then
    HAVE_IP=0
    record_reg container_network_address 0 "could not determine a non-loopback container IP"
else
    record_reg container_network_address 1
fi

rfb_banner_from() {
    # $1 = host. Prints up to 32 bytes of the VNC banner (RFB ...) or nothing.
    local out; out="$WORK/b.$$"
    timeout 6 nc -w 3 "$1" 5900 </dev/null >"$out" 2>/dev/null
    head -c 32 "$out"; rm -f "$out"
}

###############################################################################
# PoC part 1: inspect EVERY 5900 listener — ANY non-loopback binding is exposure.
# Recorded unconditionally: with no listeners at all (killed VNC) there is no
# non-loopback binding, so this passes and the regression witnesses the kill.
###############################################################################
NONLOOP=""
for addr in $LISTENERS; do
    host="${addr%:*}"   # strip trailing :5900
    case "$host" in
        127.*|::1) : ;;
        *)         NONLOOP="$NONLOOP $addr" ;;   # 0.0.0.0, ::, or a real IP
    esac
done
if [ -n "$NONLOOP" ]; then
    record_poc no_nonloopback_listener 0 \
        "VNC has a non-loopback listener on 5900 —$NONLOOP still directly exposed (all listeners: $(echo $LISTENERS))"
else
    record_poc no_nonloopback_listener 1
fi

###############################################################################
# PoC part 2: the untrusted IP must not complete a VNC (RFB) handshake.
###############################################################################
if [ "$HAVE_IP" = "1" ]; then
    if rfb_banner_from "$IP" | grep -q 'RFB'; then
        record_poc untrusted_no_rfb 0 \
            "VNC completed an RFB handshake on the untrusted IP $IP:5900 — still directly exposed to untrusted networks"
    else
        record_poc untrusted_no_rfb 1
    fi
else
    echo "  [SKIP] (poc) untrusted_no_rfb: no non-loopback IP to probe from."
fi

###############################################################################
# PoC part 3: the persistence marker must be present (otherwise the binding would
# revert to all-interfaces on reboot). Filesystem fact — independent of liveness.
###############################################################################
if [ -f /root/.vnc/bound-local ]; then
    record_poc bound_local_marker 1
else
    record_poc bound_local_marker 0 \
        "loopback-bind policy marker /root/.vnc/bound-local not present (the binding would revert to all-interfaces on reboot)"
fi

###############################################################################
# Regression: a REAL VNC server must answer on loopback with an RFB banner
# (the SSH-tunnel target). A placeholder listener that speaks no RFB FAILS.
###############################################################################
LOOP_BANNER=$(rfb_banner_from "127.0.0.1") || true
if echo "$LOOP_BANNER" | grep -q 'RFB'; then
    record_reg loopback_rfb_server 1
else
    record_reg loopback_rfb_server 0 \
        "no genuine VNC (RFB) server on 127.0.0.1:5900 — the loopback tunnel target does not speak RFB; banner=$(echo -n "$LOOP_BANNER" | tr -d '\r\n')"
fi

if pgrep -x sshd >/dev/null 2>&1 && netstat -tln 2>/dev/null | grep -q ':22'; then
    record_reg sshd_tunnel_path 1
else
    record_reg sshd_tunnel_path 0 "sshd not listening on 22 — SSH-tunnel access path broken"
fi

verify_finish
