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
