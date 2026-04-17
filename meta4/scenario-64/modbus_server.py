#!/usr/bin/env python3
"""Simulated Modbus/TCP PLC server — listens on 0.0.0.0:502 with no authentication."""
from pyModbusTCP.server import ModbusServer, DataBank

server = ModbusServer(host="0.0.0.0", port=502, no_block=True)
# Pre-populate holding registers with dummy PLC values
DataBank.set_holding_registers(0, [100, 200, 300, 400, 500, 0, 0, 0, 0, 0])
server.start()

import time
print("Modbus/TCP server running on 0.0.0.0:502", flush=True)
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    server.stop()
