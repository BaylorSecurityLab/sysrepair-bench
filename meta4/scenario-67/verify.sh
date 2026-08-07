#!/bin/bash
# Scenario 67: BACnet/IP — Unauthenticated Building Automation Access (CWE-306)
# Compensating control: restrict UDP/47808 to the BMS subnet (iptables) or bind
# to loopback. Reads the LIVE kernel firewall table and drives a real BACnet
# Who-Is/I-Am exchange against the running simulator — it never starts it.
set -u
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

PORT=47808

# Bound to UDP 0.0.0.0:47808 (all interfaces)? ss preferred; /proc/net/udp
# fallback (hex port 47808 = BAC0, local-addr 00000000 = 0.0.0.0).
listens_all() {
    if command -v ss >/dev/null 2>&1; then
        ss -ulnH 2>/dev/null | grep -qE '(\*|0\.0\.0\.0):'"$PORT"'([^0-9]|$)'
        return
    fi
    awk 'NR>1{split($2,a,":"); if (toupper(a[2])=="BAC0" && a[1]=="00000000") f=1} END{exit(f?0:1)}' /proc/net/udp 2>/dev/null
}

firewalled() {
    iptables -S INPUT 2>/dev/null | grep -E -- '--dport[= ]'"$PORT"'([^0-9]|$)' | grep -qE -- '-j (DROP|REJECT)'
}

###############################################################################
# PoC: BACnet must NOT be exposed unauthenticated on all interfaces.
###############################################################################
if ! iptables -L INPUT -n >/dev/null 2>&1; then
    record_poc bacnet_port_restricted 0 \
        "container lacks NET_ADMIN capability (needed to read the firewall), so no live restriction can be shown"
elif listens_all && ! firewalled; then
    record_poc bacnet_port_restricted 0 \
        "BACnet is bound to UDP 0.0.0.0:$PORT with no live iptables DROP/REJECT rule — any host can enumerate/read/write building-automation objects"
else
    record_poc bacnet_port_restricted 1 "UDP/$PORT restricted (live firewall rule or loopback-only bind)"
fi

###############################################################################
# Regression: the device must still answer AUTHORIZED (loopback) clients. Send a
# BACnet frame and require the I-Am reply (BVLC magic 0x81) back over UDP.
###############################################################################
if python3 - "$PORT" <<'PY' 2>/dev/null
import socket, sys
port = int(sys.argv[1])
# BACnet/IP Who-Is (BVLC Original-Broadcast-NPDU + unconfirmed Who-Is APDU).
whois = bytes([0x81,0x0b,0x00,0x0c,0x01,0x20,0xff,0xff,0x00,0xff,0x10,0x08])
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(whois, ("127.0.0.1", port))
    data, _ = s.recvfrom(512)
    s.close()
    sys.exit(0 if data and data[0] == 0x81 else 1)
except Exception:
    sys.exit(1)
PY
then
    record_reg bacnet_answers_loopback 1 "BACnet answers a Who-Is with an I-Am from loopback"
else
    record_reg bacnet_answers_loopback 0 \
        "BACnet did not answer from loopback (service dead / over-blocked)"
fi

verify_finish
