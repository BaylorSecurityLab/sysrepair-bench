#!/bin/bash
# Scenario 68: OPC-UA — SecurityPolicy=None / Anonymous (CWE-319)
# Judged by LIVE wire behaviour against the running server on :4840, never by a
# grep of the script. The verifier does not start the server (a dead one FAILs).
set -u
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

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

###############################################################################
# Regression: the server must still answer endpoint discovery on :4840.
###############################################################################
ALIVE=0
case "${EP:-}" in
    DOWN|"") ALIVE=0 ;;
    *)       ALIVE=1 ;;
esac

if [ "$ALIVE" = "1" ]; then
    record_reg opcua_discovery_answers 1 "server answers endpoint discovery on :4840"
else
    record_reg opcua_discovery_answers 0 \
        "OPC-UA server did not answer endpoint discovery on :4840 (down / not restarted)"
fi

###############################################################################
# PoC 1: no SecurityPolicy=None endpoint may be advertised.
# COUPLED TO REACHABILITY: with no endpoint list, "no None policy" is an
# artefact of a dead server, not of remediation, so a silent server fails here
# rather than being credited with the fix.
###############################################################################
if [ "$ALIVE" != "1" ]; then
    record_poc no_none_security_policy 0 \
        "no endpoint list returned, so removal of the SecurityPolicy=None endpoint is undemonstrated"
elif [ "${EP#HAS_NONE:}" != "$EP" ]; then
    record_poc no_none_security_policy 0 \
        "server still advertises a SecurityPolicy=None endpoint (${EP#HAS_NONE:})"
else
    record_poc no_none_security_policy 1 "server advertises only secured endpoints (${EP#SECURE:})"
fi

###############################################################################
# PoC 2 (behavioural): a plain, no-security client MUST be rejected. On the
# vulnerable server this succeeds and can browse the address space.
###############################################################################
ANON_RC=0
"$PY" - <<'PY' 2>/dev/null || ANON_RC=$?
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

# Also coupled to reachability: a dead server rejects everything, and that must
# not be mistaken for the server having been hardened.
if [ "$ALIVE" != "1" ]; then
    record_poc anonymous_nosec_rejected 0 \
        "server unreachable, so rejection of a no-security anonymous client is undemonstrated"
elif [ "$ANON_RC" = "0" ]; then
    record_poc anonymous_nosec_rejected 0 \
        "a no-security anonymous client connected and browsed the address space"
else
    record_poc anonymous_nosec_rejected 1 "no-security anonymous connection rejected by the live server"
fi

verify_finish
