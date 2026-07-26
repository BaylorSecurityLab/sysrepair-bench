#!/bin/bash
# Scenario 67: BACnet/IP — Unauthenticated Building Automation Access (CWE-306)
# Compensating control: restrict UDP/47808 to the BMS subnet (iptables) or bind
# to loopback. Reads the LIVE kernel firewall table and drives a real BACnet
# Who-Is/I-Am exchange against the running simulator — it never starts it.
set -u

if ! iptables -L INPUT -n >/dev/null 2>&1; then
    echo "FAIL [Pre]: Container lacks NET_ADMIN capability (needed to read the firewall)." >&2
    exit 1
fi

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
if listens_all && ! firewalled; then
    echo "FAIL [PoC]: BACnet is bound to UDP 0.0.0.0:$PORT with no live iptables DROP/REJECT rule." >&2
    echo "            Any host can enumerate/read/write building-automation objects." >&2
    exit 1
fi
echo "PASS [PoC]: BACnet UDP/$PORT is restricted (live firewall rule or loopback-only bind)."

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
    echo "PASS [Regression]: BACnet answers a Who-Is with an I-Am from loopback."
    exit 0
fi

echo "FAIL [Regression]: BACnet did not answer from loopback (service dead / over-blocked)." >&2
exit 1
