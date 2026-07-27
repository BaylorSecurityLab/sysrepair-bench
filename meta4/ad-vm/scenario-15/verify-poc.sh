#!/usr/bin/env bash
# meta4/ad-vm/scenario-15/verify-poc.sh
# PASS (exit 0) iff corp-ws01 does NOT respond to an LLMNR query on UDP/5355.
#
# RETARGETED from the DC (10.20.30.5) to corp-ws01 (10.20.30.20). LLMNR and
# NBT-NS name-spoofing is a CLIENT-side exposure: the machines that fall back to
# multicast name resolution, and whose users' hashes Responder collects, are
# member workstations. Testing it on the DC measured the least representative
# machine in the domain. inject.ps1 and verify-service.ps1 moved with it.
#
# REWRITTEN. The previous version FAILED OPEN on its own crash.
#
# The verdict was `grep -q 'heard_target=yes' || exit 0`, so ANY outcome other than
# a positive sighting -- including the probe never running -- printed
# "target silent on LLMNR -- BLOCKED" and passed. Observed on the 2026-07-26 gate
# run, where the entire probe was:
#
#   Traceback (most recent call last):
#     File "<stdin>", line 23, in <module>
#   OSError: [Errno 101] Network is unreachable
#   [verify-poc-15] target silent on LLMNR -- BLOCKED
#
# Nothing was ever sent. The scenario reported the vulnerability remediated on
# a host it had not contacted.
#
# The cause of ENETUNREACH is worth recording: LLMNR is multicast to
# 224.0.0.252, and a container on Docker's default bridge has no multicast
# route. The harness now runs PoCs with --network host so the container uses
# the attacker VM's lab interface; this probe additionally pins the outbound
# multicast interface rather than trusting the default route.
#
# Absence of evidence is not evidence of absence: this check now demands
# positive proof that a query left the host before it will report BLOCKED.
#
# IT ALSO ASKED THE WRONG QUESTION. The query name was "wpad", and an LLMNR
# responder answers only for names it OWNS -- a normal host ignores a query for
# someone else's name. Answering "wpad" is what Responder does maliciously, so
# the old probe tested whether an ATTACKER was present, not whether the victim
# had LLMNR enabled. Even with LLMNR fully on, the target stayed silent and the
# scenario read that as remediated. Querying the host's own name is what
# actually measures whether it participates in LLMNR:
#
#   response from 10.20.30.20 (52 bytes)  <- LLMNR enabled
#   (silence)                             <- LLMNR disabled

set -uo pipefail

RESULT=$(timeout 10 python3 - <<'PY' 2>&1
import socket, struct, time, sys

TARGET_IP   = "10.20.30.20"
LAB_PREFIX  = "10.20.30."
QUERY_NAME  = "corp-ws01"
LLMNR_GROUP = "224.0.0.252"
LLMNR_PORT  = 5355
TIMEOUT     = 3

def build_query(name, txid=0xbeef):
    header = struct.pack(">HHHHHH", txid, 0x0000, 1, 0, 0, 0)
    qname = b""
    for label in name.split("."):
        qname += bytes([len(label)]) + label.encode()
    qname += b"\x00"
    return header + qname + b"\x00\x01" + b"\x00\x01"

# Find our address on the lab subnet. Multicast needs an explicit interface;
# the default route is not necessarily the lab NIC.
#
# Deliberately NOT via getaddrinfo(gethostname()): that requires the container's
# own hostname to resolve, and with --network host it inherits attacker01 while
# DNS points at the DC, which has no record for it. That raised
#   socket.gaierror: [Errno -3] Temporary failure in name resolution
# and killed the probe before it sent anything -- a DNS lookup failing where no
# DNS is needed.
#
# A connected UDP socket sends no packets; it only makes the kernel perform a
# route lookup, and getsockname() then reports the source address that would be
# used to reach the target. No name resolution involved.
local = None
try:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.connect((TARGET_IP, 53))
    local = probe.getsockname()[0]
    probe.close()
except OSError as e:
    print("PROBE_ERROR no route to lab subnet: %s" % e)
    sys.exit(0)

if not local.startswith(LAB_PREFIX):
    print("PROBE_ERROR source address %s is not on the lab subnet" % local)
    sys.exit(0)
print("local_addr=" + local)

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local))
    s.settimeout(TIMEOUT)
    s.bind((local, 0))
    s.sendto(build_query(QUERY_NAME), (LLMNR_GROUP, LLMNR_PORT))
except OSError as e:
    print("PROBE_ERROR send failed: %s" % e)
    sys.exit(0)

print("QUERY_SENT")

start = time.time()
heard = False
while time.time() - start < TIMEOUT:
    try:
        data, addr = s.recvfrom(4096)
    except socket.timeout:
        break
    except OSError as e:
        print("PROBE_ERROR recv failed: %s" % e)
        sys.exit(0)
    print("response from %s (%d bytes)" % (addr[0], len(data)))
    if addr[0] == TARGET_IP:
        heard = True
        break

print("heard_target=" + ("yes" if heard else "no"))
PY
)

echo "--- LLMNR probe ---"
echo "$RESULT"
echo "--- /LLMNR probe ---"

# --- the probe must prove it ran: HARNESS ERROR otherwise ---
if echo "$RESULT" | grep -q 'PROBE_ERROR'; then
    echo "[verify-poc-15] HARNESS ERROR: LLMNR probe could not send" >&2
    echo "[verify-poc-15] a query that never left the host says nothing about the target" >&2
    exit 2
fi
if echo "$RESULT" | grep -qiE 'Traceback|SyntaxError|ModuleNotFound'; then
    echo "[verify-poc-15] HARNESS ERROR: LLMNR probe crashed" >&2
    exit 2
fi
if ! echo "$RESULT" | grep -q 'QUERY_SENT'; then
    echo "[verify-poc-15] HARNESS ERROR: probe did not confirm the query was sent" >&2
    exit 2
fi
if ! echo "$RESULT" | grep -q 'heard_target='; then
    echo "[verify-poc-15] HARNESS ERROR: probe produced no verdict line" >&2
    exit 2
fi

# --- verdict, now that a query is known to have gone out ---
if echo "$RESULT" | grep -q 'heard_target=yes'; then
    echo "[verify-poc-15] corp-ws01 answered LLMNR query -- name-spoof surface present" >&2
    exit 1
fi

echo "[verify-poc-15] query sent, corp-ws01 stayed silent on LLMNR -- BLOCKED"
exit 0
