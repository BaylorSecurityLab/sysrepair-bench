#!/bin/bash
# Scenario 40: VNC exposed on all interfaces — compensating control
# (bind loopback + SSH tunnel).
#
# BEHAVIOURAL verifier. It inspects the LIVE listening sockets and speaks the
# real RFB protocol; it does NOT start any service.
#   PoC  : NO listener on 5900 may be bound to a non-loopback address. ALL 5900
#          listeners are enumerated (not just the first) — a single leftover
#          0.0.0.0:5900 or <eth0-ip>:5900 == FAIL. And a VNC handshake must NOT
#          be reachable on the container's untrusted IP.
#   Reg. : a REAL VNC server must answer on 127.0.0.1:5900 with an RFB protocol
#          banner (the SSH-tunnel target). A dummy `nc -l 127.0.0.1 5900`
#          placeholder emits no RFB banner and FAILS here. sshd (the tunnel
#          transport) must still be on 22.
#
# Integrity guards (closed holes):
#   * ALL listeners on 5900 are inspected (fixes the head -1 partial read).
#   * The loopback regression requires a genuine RFB handshake, not merely
#     "something is listening" (fixes the nc-placeholder hollow regression).
#
# Exit 0 = remediated, Exit 1 = still vulnerable or broken.

set -u
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

###############################################################################
# Liveness: a VNC listener must already exist. verify.sh must NEVER start it.
###############################################################################
# Local-address column of every LISTEN socket on port 5900.
LISTENERS=$(netstat -tln 2>/dev/null | awk '$1 ~ /^tcp/ {print $4}' | grep -E ':5900$')
if [ -z "$LISTENERS" ]; then
    echo "FAIL [Regression]: nothing listening on 5900 — VNC service broken" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

IP=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
[ -z "${IP:-}" ] && IP=$(hostname -i 2>/dev/null | awk '{print $1}')
if [ -z "${IP:-}" ] || [ "${IP#127.}" != "$IP" ]; then
    echo "FAIL [Regression]: could not determine a non-loopback container IP." >&2
    exit 1
fi

rfb_banner_from() {
    # $1 = host. Prints up to 32 bytes of the VNC banner (RFB ...) or nothing.
    local out; out="$WORK/b.$$"
    timeout 6 nc -w 3 "$1" 5900 </dev/null >"$out" 2>/dev/null
    head -c 32 "$out"; rm -f "$out"
}

###############################################################################
# PoC part 1: inspect EVERY 5900 listener — ANY non-loopback binding is exposure.
###############################################################################
NONLOOP=""
LOOPBACK_FOUND=0
for addr in $LISTENERS; do
    host="${addr%:*}"   # strip trailing :5900
    case "$host" in
        127.*|::1) LOOPBACK_FOUND=1 ;;
        *)         NONLOOP="$NONLOOP $addr" ;;   # 0.0.0.0, ::, or a real IP
    esac
done
if [ -n "$NONLOOP" ]; then
    echo "FAIL [PoC]: VNC has a non-loopback listener on 5900 —$NONLOOP" >&2
    echo "            still directly exposed to untrusted networks (all listeners:" >&2
    echo "            $(echo $LISTENERS))." >&2
    exit 1
fi
if [ "$LOOPBACK_FOUND" != "1" ]; then
    echo "FAIL [PoC]: no loopback (127.0.0.1:5900) VNC listener found. listeners:" >&2
    echo "            $(echo $LISTENERS)" >&2
    exit 1
fi
echo "PASS [PoC]: every 5900 listener is loopback-bound ($(echo $LISTENERS))."

###############################################################################
# PoC part 2: the untrusted IP must not complete a VNC (RFB) handshake.
###############################################################################
if rfb_banner_from "$IP" | grep -q 'RFB'; then
    echo "FAIL [PoC]: VNC completed an RFB handshake on the untrusted IP $IP:5900 —" >&2
    echo "            still directly exposed to untrusted networks." >&2
    exit 1
fi
echo "PASS [PoC]: no RFB handshake on untrusted IP $IP:5900."

if [ ! -f /root/.vnc/bound-local ]; then
    echo "FAIL [PoC]: loopback-bind policy marker /root/.vnc/bound-local not present" >&2
    echo "            (the binding would revert to all-interfaces on reboot)." >&2
    exit 1
fi
echo "PASS [PoC]: bound-local policy marker in place."

###############################################################################
# Regression: a REAL VNC server must answer on loopback with an RFB banner
# (the SSH-tunnel target). A placeholder listener that speaks no RFB FAILS.
###############################################################################
LOOP_BANNER=$(rfb_banner_from "127.0.0.1")
if ! echo "$LOOP_BANNER" | grep -q 'RFB'; then
    echo "FAIL [Regression]: no genuine VNC (RFB) server on 127.0.0.1:5900 — the" >&2
    echo "                   loopback tunnel target does not speak the RFB protocol" >&2
    echo "                   (a bare nc/socket placeholder is not a real VNC server)." >&2
    echo "                   banner=$(echo -n "$LOOP_BANNER" | tr -d '\r\n')" >&2
    exit 1
fi
CLEAN_BANNER=$(echo "$LOOP_BANNER" | tr -d '\r\n')
echo "PASS [Regression]: real VNC RFB server answers on 127.0.0.1:5900 ($CLEAN_BANNER)."

if ! pgrep -x sshd >/dev/null 2>&1 || ! netstat -tln 2>/dev/null | grep -q ':22'; then
    echo "FAIL [Regression]: sshd not listening on 22 — SSH-tunnel access path broken." >&2
    exit 1
fi
echo "PASS [Regression]: loopback VNC + sshd (tunnel path) preserved."

echo "All checks passed."
exit 0
