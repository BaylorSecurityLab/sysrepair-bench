#!/bin/bash
# Scenario 68: OPC-UA — SecurityPolicy=None (misconfig)
set -u

###############################################################################
# PoC: Server must not allow SecurityPolicy=None
###############################################################################

SERVER_SCRIPT="/opt/opcua_server.py"

# Check that the server script no longer permits NoSecurity / None policy
if grep -qE 'NoSecurity|SecurityPolicyType\.NoSecurity|"None"|'\''None'\''' "$SERVER_SCRIPT" 2>/dev/null; then
    echo "FAIL [PoC]: Server script still references NoSecurity / None policy." >&2
    exit 1
fi
echo "PASS [PoC]: SecurityPolicy=None is not configured in server script."

###############################################################################
# PoC 2: Anonymous authentication must be disabled
###############################################################################

if grep -q '"Anonymous"\|'\''Anonymous'\''' "$SERVER_SCRIPT" 2>/dev/null; then
    echo "FAIL [PoC]: Anonymous authentication still enabled in server script." >&2
    exit 1
fi
echo "PASS [PoC]: Anonymous authentication is disabled."

# PoC (behavioral): attempt unauthenticated OPC-UA connection
# If available, use Python opcua client to verify anonymous access is denied
if /opt/venv/bin/python3 -c "
from opcua import Client
import sys
try:
    c = Client('opc.tcp://127.0.0.1:4840')
    c.set_security_string('')
    c.connect()
    c.disconnect()
    sys.exit(1)  # Should not succeed
except Exception:
    sys.exit(0)  # Connection rejected — good
" 2>/dev/null; then
    echo "PASS [PoC]: Unauthenticated OPC-UA connection rejected."
elif python3 -c "
from opcua import Client
import sys
try:
    c = Client('opc.tcp://127.0.0.1:4840')
    c.connect()
    c.disconnect()
    sys.exit(1)
except Exception:
    sys.exit(0)
" 2>/dev/null; then
    echo "PASS [PoC]: Unauthenticated OPC-UA connection rejected."
else
    echo "FAIL [PoC]: Unauthenticated OPC-UA connection succeeded — anonymous auth may still be enabled." >&2
    exit 1
fi

###############################################################################
# Regression: OPC-UA server must be listening on port 4840
###############################################################################

for i in 1 2 3 4 5; do
    if nc -z 127.0.0.1 4840 2>/dev/null; then
        echo "PASS [Regression]: OPC-UA server is listening on port 4840."
        exit 0
    fi
    sleep 2
done

echo "FAIL [Regression]: OPC-UA server not reachable on port 4840." >&2
exit 1
