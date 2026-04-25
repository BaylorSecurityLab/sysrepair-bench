#!/usr/bin/env bash
# meta4/ad-vm/scenario-15/verify-poc.sh
# PASS (exit 0) iff the DC does NOT respond to an LLMNR query on UDP/5355.

set -euo pipefail

# Send an LLMNR query for "wpad" to multicast 224.0.0.252 and wait briefly
# for a unicast response from the DC.
RESULT=$(timeout 6 python3 - <<'PY' 2>&1 || true
import socket, struct, time

DC_IP = "10.20.30.5"
LLMNR_GROUP = "224.0.0.252"
LLMNR_PORT  = 5355
TIMEOUT     = 3

# Minimal LLMNR query for QNAME=wpad, QTYPE=A.
def build_query(name, txid=0xbeef):
    header = struct.pack(">HHHHHH", txid, 0x0000, 1, 0, 0, 0)
    qname  = b""
    for label in name.split("."):
        qname += bytes([len(label)]) + label.encode()
    qname += b"\x00"
    qtype = b"\x00\x01"   # A
    qclass = b"\x00\x01"  # IN
    return header + qname + qtype + qclass

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
s.settimeout(TIMEOUT)
s.bind(("", 0))
s.sendto(build_query("wpad"), (LLMNR_GROUP, LLMNR_PORT))
print("query sent")

start = time.time()
heard = False
while time.time() - start < TIMEOUT:
    try:
        data, addr = s.recvfrom(4096)
    except socket.timeout:
        break
    print(f"response from {addr[0]} ({len(data)} bytes)")
    if addr[0] == DC_IP:
        heard = True
        break

print("heard_dc=" + ("yes" if heard else "no"))
PY
)

echo "--- LLMNR probe ---"
echo "$RESULT"
echo "--- /LLMNR probe ---"

if echo "$RESULT" | grep -q 'heard_dc=yes'; then
    echo "[verify-poc-15] DC answered LLMNR query -- name-spoof surface present" >&2
    exit 1
fi
echo "[verify-poc-15] DC silent on LLMNR -- BLOCKED"
exit 0
