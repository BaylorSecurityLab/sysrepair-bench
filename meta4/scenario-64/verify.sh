#!/bin/bash
# Scenario 64: Modbus/TCP — Unauthenticated PLC Access (CWE-306)
# Compensating control: restrict TCP/502 to trusted sources (iptables) or bind
# to loopback. This verifier reads the LIVE kernel firewall table and drives a
# real Modbus read against the running simulator — it never starts the service.
set -u
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

###############################################################################
# The image CMD boots the simulator (see .preserve-cmd); a dead daemon is a
# FAIL. verify.sh must NOT start it.
###############################################################################
PORT=502

# Is anything bound to 0.0.0.0:502 (all interfaces)? Prefer ss; fall back to
# /proc/net/tcp (hex port 502 = 01F6, local-addr 00000000 = 0.0.0.0).
listens_all() {
    if command -v ss >/dev/null 2>&1; then
        ss -tlnH 2>/dev/null | grep -qE '(\*|0\.0\.0\.0):'"$PORT"'([^0-9]|$)'
        return
    fi
    awk 'NR>1{split($2,a,":"); if (a[2]=="01F6" && a[1]=="00000000") f=1} END{exit(f?0:1)}' /proc/net/tcp 2>/dev/null
}

# Is there a live DROP/REJECT rule for dport 502 in the running INPUT chain?
# iptables -S prints rules as "-A INPUT ... --dport 502 ... -j DROP".
firewalled() {
    iptables -S INPUT 2>/dev/null | grep -E -- '--dport[= ]'"$PORT"'([^0-9]|$)' | grep -qE -- '-j (DROP|REJECT)'
}

###############################################################################
# PoC: the PLC must NOT be exposed unauthenticated on all interfaces. It is
# remediated if EITHER a live firewall rule drops untrusted traffic to :502 OR
# the daemon is no longer bound to 0.0.0.0.
###############################################################################
if ! iptables -L INPUT -n >/dev/null 2>&1; then
    record_poc modbus_port_restricted 0 \
        "container lacks NET_ADMIN capability (needed to read the firewall), so no live restriction can be shown"
elif listens_all && ! firewalled; then
    record_poc modbus_port_restricted 0 \
        "Modbus is bound to 0.0.0.0:$PORT with no live iptables DROP/REJECT rule — any network-reachable client can read/write PLC registers"
else
    record_poc modbus_port_restricted 1 "TCP/$PORT restricted (live firewall rule or loopback-only bind)"
fi

###############################################################################
# Regression: the PLC must still answer AUTHORIZED (loopback) clients with a
# real Modbus read of holding registers.
###############################################################################
if /opt/venv/bin/python3 -c "
import sys
from pyModbusTCP.client import ModbusClient
c = ModbusClient(host='127.0.0.1', port=$PORT, auto_open=True, timeout=3)
regs = c.read_holding_registers(0, 10)
sys.exit(0 if regs else 1)
" 2>/dev/null; then
    record_reg modbus_serves_loopback 1 "Modbus answers a live register read from loopback"
else
    record_reg modbus_serves_loopback 0 \
        "Modbus did not answer a register read from loopback (service dead / over-blocked)"
fi

verify_finish
