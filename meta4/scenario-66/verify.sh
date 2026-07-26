#!/bin/bash
# Scenario 66: IPMI — Cipher-Zero Auth Bypass (CWE-306 / CWE-327)
# Compensating control: restrict UDP/623 to the management VLAN (iptables) and
# remove cipher suite 0 from the BMC config. The firewall check reads the LIVE
# kernel table; the cipher check asserts config state (the simulator does not
# enforce cipher suites). This verifier never starts the service.
set -u

if ! iptables -L INPUT -n >/dev/null 2>&1; then
    echo "FAIL [Pre]: Container lacks NET_ADMIN capability (needed to read the firewall)." >&2
    exit 1
fi

PORT=623

firewalled() {
    iptables -S INPUT 2>/dev/null | grep -E -- '--dport[= ]'"$PORT"'([^0-9]|$)' | grep -qE -- '-j (DROP|REJECT)'
}

###############################################################################
# PoC 1: UDP 623 must be firewalled from untrusted sources (LIVE kernel table).
###############################################################################
if ! firewalled; then
    echo "FAIL [PoC 1]: No live iptables DROP/REJECT rule for UDP/$PORT — BMC is exposed." >&2
    exit 1
fi
echo "PASS [PoC 1]: iptables restricts UDP/$PORT (live rule)."

###############################################################################
# PoC 2: cipher suite 0 (null cipher) must be removed from /etc/ipmi.conf.
# Match only the cipher_suite_ids value list; treat 0 as a standalone token.
###############################################################################
CIPHER_LINE=$(grep -E '^[[:space:]]*cipher_suite_ids[[:space:]]*=' /etc/ipmi.conf 2>/dev/null | sed 's/#.*//')
if [ -z "$CIPHER_LINE" ]; then
    echo "FAIL [PoC 2]: cipher_suite_ids not found in /etc/ipmi.conf." >&2
    exit 1
fi
VALUES=$(echo "$CIPHER_LINE" | sed 's/.*=//' | tr ', ' '\n' | grep -E '^[0-9]+$')
if echo "$VALUES" | grep -qx '0'; then
    echo "FAIL [PoC 2]: cipher suite 0 (null cipher) still enabled in /etc/ipmi.conf." >&2
    exit 1
fi
echo "PASS [PoC 2]: cipher suite 0 is removed from /etc/ipmi.conf."

###############################################################################
# Regression: the BMC must still answer AUTHORIZED (loopback) clients over UDP.
# Send an RMCP ping and require any reply back.
###############################################################################
if python3 - "$PORT" <<'PY' 2>/dev/null
import socket, sys
port = int(sys.argv[1])
# RMCP presence-ping (ASF) header — the simulator replies to any datagram.
ping = bytes([0x06,0x00,0xff,0x06,0x00,0x00,0x11,0xbe,0x80,0x00,0x00,0x00])
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(ping, ("127.0.0.1", port))
    data, _ = s.recvfrom(512)
    s.close()
    sys.exit(0 if data else 1)
except Exception:
    sys.exit(1)
PY
then
    echo "PASS [Regression]: BMC answers on UDP/$PORT from loopback."
    exit 0
fi

echo "FAIL [Regression]: BMC did not answer on UDP/$PORT from loopback (service dead / over-blocked)." >&2
exit 1
