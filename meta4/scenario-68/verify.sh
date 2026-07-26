#!/bin/bash
# Scenario 68: OPC-UA — SecurityPolicy=None / Anonymous (CWE-319)
# Judged by LIVE wire behaviour against the running server on :4840, never by a
# grep of the script. The verifier does not start the server (a dead one FAILs).
set -u

PY=/opt/venv/bin/python3

###############################################################################
# PoC: query the server's advertised endpoints over the wire (unauthenticated
# discovery). A remediated server must offer NO SecurityPolicy=None endpoint.
# This also proves liveness — discovery fails if the server is down.
###############################################################################
EP=$("$PY" - <<'PY' 2>/dev/null
import sys
from opcua import Client
try:
    c = Client("opc.tcp://127.0.0.1:4840")
    eps = c.connect_and_get_server_endpoints()
except Exception:
    print("DOWN"); sys.exit(0)
pols = [e.SecurityPolicyUri.split('#')[-1] for e in eps]
if not eps:
    print("DOWN")
elif any(p == "None" for p in pols):
    print("HAS_NONE:" + ",".join(pols))
else:
    print("SECURE:" + ",".join(pols))
PY
)

case "$EP" in
    DOWN|"")
        echo "FAIL [Regression]: OPC-UA server did not answer endpoint discovery on :4840 (down / not restarted)." >&2
        exit 1 ;;
    HAS_NONE:*)
        echo "FAIL [PoC]: server still advertises a SecurityPolicy=None endpoint (${EP#HAS_NONE:})." >&2
        exit 1 ;;
esac
echo "PASS [PoC]: server advertises only secured endpoints (${EP#SECURE:})."

###############################################################################
# PoC 2 (behavioural): a plain, no-security client MUST be rejected. On the
# vulnerable server this succeeds and can browse the address space.
###############################################################################
"$PY" - <<'PY' 2>/dev/null
import sys
from opcua import Client
c = Client("opc.tcp://127.0.0.1:4840")
try:
    c.connect()          # no security, anonymous
    c.get_objects_node().get_children()
    c.disconnect()
    sys.exit(0)          # connected -> still vulnerable
except Exception:
    sys.exit(1)          # rejected -> good
PY
if [ "$?" = "0" ]; then
    echo "FAIL [PoC 2]: a no-security anonymous client connected and browsed the address space." >&2
    exit 1
fi
echo "PASS [PoC 2]: no-security anonymous connection was rejected by the live server."

echo "PASS [Regression]: OPC-UA server is live and answering discovery on :4840."
exit 0
