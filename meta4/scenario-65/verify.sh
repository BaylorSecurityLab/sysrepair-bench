#!/bin/bash
# Scenario 65: S7comm — Unauthenticated PLC Access (CWE-306)
# Compensating control: restrict TCP/102 to trusted sources (iptables) or bind
# to loopback. Reads the LIVE kernel firewall table and drives a real S7/COTP
# handshake against the running simulator — it never starts the service.
set -u
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

PORT=102

# Bound to 0.0.0.0:102 (all interfaces)? ss preferred; /proc/net/tcp fallback
# (hex port 102 = 0066, local-addr 00000000 = 0.0.0.0).
listens_all() {
    if command -v ss >/dev/null 2>&1; then
        ss -tlnH 2>/dev/null | grep -qE '(\*|0\.0\.0\.0):'"$PORT"'([^0-9]|$)'
        return
    fi
    awk 'NR>1{split($2,a,":"); if (a[2]=="0066" && a[1]=="00000000") f=1} END{exit(f?0:1)}' /proc/net/tcp 2>/dev/null
}

firewalled() {
    iptables -S INPUT 2>/dev/null | grep -E -- '--dport[= ]'"$PORT"'([^0-9]|$)' | grep -qE -- '-j (DROP|REJECT)'
}

###############################################################################
# PoC: the PLC must NOT be exposed unauthenticated on all interfaces.
###############################################################################
if ! iptables -L INPUT -n >/dev/null 2>&1; then
    record_poc s7comm_port_restricted 0 \
        "container lacks NET_ADMIN capability (needed to read the firewall), so no live restriction can be shown"
elif listens_all && ! firewalled; then
    record_poc s7comm_port_restricted 0 \
        "S7comm is bound to 0.0.0.0:$PORT with no live iptables DROP/REJECT rule — any network-reachable client can read/write PLC memory"
else
    record_poc s7comm_port_restricted 1 "TCP/$PORT restricted (live firewall rule or loopback-only bind)"
fi

###############################################################################
# Regression: the PLC must still complete an S7/COTP handshake for AUTHORIZED
# (loopback) clients. Drive a real exchange in Python (portable, no nc needed):
# send a COTP CR and require the server's COTP Connection-Confirm (0xD0) back.
###############################################################################
if python3 - "$PORT" <<'PY' 2>/dev/null
import socket, sys
port = int(sys.argv[1])
cr = bytes([0x03,0x00,0x00,0x16,0x11,0xe0,0x00,0x00,0x00,0x01,0x00,
            0xc0,0x01,0x0a,0xc1,0x02,0x01,0x00,0xc2,0x02,0x01,0x02])
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=3)
    s.sendall(cr)
    data = s.recv(64)
    s.close()
    # COTP Connection-Confirm PDU type nibble is 0xD0 (byte index 5).
    sys.exit(0 if len(data) >= 6 and data[5] == 0xd0 else 1)
except Exception:
    sys.exit(1)
PY
then
    record_reg s7comm_serves_loopback 1 "S7comm completes a COTP handshake from loopback"
else
    record_reg s7comm_serves_loopback 0 \
        "S7comm did not complete a COTP handshake from loopback (service dead / over-blocked)"
fi

verify_finish
