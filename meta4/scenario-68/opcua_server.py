#!/usr/bin/env python3
"""OPC-UA server with SecurityPolicy=None and anonymous authentication.
This is a misconfiguration: all communication is unencrypted and unauthenticated.
"""
from opcua import Server
from opcua.ua import SecurityPolicyType

server = Server()
server.set_endpoint("opc.tcp://0.0.0.0:4840/freeopcua/server/")
server.set_server_name("Vulnerable OPC-UA Server")

# VULNERABLE: SecurityPolicy=None allows cleartext unauthenticated sessions
server.set_security_policy([SecurityPolicyType.NoSecurity])

# VULNERABLE: anonymous access enabled (default)
server.set_security_IDs(["Anonymous"])

# Populate a simple address space
uri = "http://example.org/opcua/ics"
idx = server.register_namespace(uri)
objects = server.get_objects_node()
plc = objects.add_object(idx, "PLC")
plc.add_variable(idx, "Temperature", 72.5)
plc.add_variable(idx, "Pressure", 14.7)
plc.add_variable(idx, "Setpoint", 75.0)

server.start()
print("OPC-UA server running on opc.tcp://0.0.0.0:4840 (SecurityPolicy=None)", flush=True)

import time
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    server.stop()
