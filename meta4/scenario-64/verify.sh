#!/bin/bash
# Scenario 64: Modbus/TCP — Unauthenticated PLC Access
set -u

if ! iptables -L INPUT -n >/dev/null 2>&1; then
    echo "FAIL [Pre]: Container lacks NET_ADMIN capability." >&2
    exit 1
fi

###############################################################################
# PoC: Modbus port must not be accessible from unauthorized sources
###############################################################################

if ss -tlnp | grep ':502' | grep -q '0.0.0.0'; then
    if ! iptables -L INPUT -n 2>/dev/null | grep -q 'dpt:502.*DROP\|dpt:502.*REJECT'; then
        echo "FAIL [PoC]: Modbus on 0.0.0.0:502 with no firewall restriction." >&2
        exit 1
    fi
fi
echo "PASS [PoC]: Modbus port 502 is restricted."

###############################################################################
# Regression: Modbus must still respond to authorized connections
###############################################################################

if /opt/venv/bin/python3 -c "
from pyModbusTCP.client import ModbusClient
c = ModbusClient(host='127.0.0.1', port=502, auto_open=True)
regs = c.read_holding_registers(0, 10)
exit(0 if regs else 1)
" 2>/dev/null; then
    echo "PASS [Regression]: Modbus responds on localhost."
    exit 0
fi

echo "FAIL [Regression]: Modbus not responding on localhost." >&2
exit 1
