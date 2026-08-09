#!/bin/bash
# Scenario 46: Neo4j 3.4 - Shell Server RMI Deserialization RCE (CVE-2021-34371)
#
# Dynamic check: confirm the RMI Shell Server listener on TCP 1337 is actually
# bound on the LIVE node. The stock image binds 1337 (verified empirically);
# disabling dbms.shell.enabled and restarting neo4j unbinds it. The listener is
# detected by parsing /proc/net/tcp{,6} - the image has no `ss`/`netstat`, so
# the original `ss -tlnp | grep :1337` silently passed even while 1337 was up.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "unbound the shell server but killed neo4j" is reported as
# security_pass / regression_pass rather than a bare exit 1. See lib/verifylib.sh.
#
# The Browser regression check is hoisted ABOVE the runtime listener PoC so it
# can double as the liveness gate: a DEAD neo4j also stops listening on 1337,
# and that must never be credited as "the shell server was disabled".
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

NEO4J_CONF="/var/lib/neo4j/conf/neo4j.conf"
[ -f "$NEO4J_CONF" ] || NEO4J_CONF="/etc/neo4j/neo4j.conf"

###############################################################################
# PoC (config): Shell Server must be disabled
###############################################################################

if grep -qE '^\s*dbms\.shell\.enabled\s*=\s*true' "$NEO4J_CONF" 2>/dev/null; then
    record_poc shell_server_disabled_in_conf 0 \
        "neo4j.conf has dbms.shell.enabled=true - CVE-2021-34371 reachable"
else
    record_poc shell_server_disabled_in_conf 1
fi

###############################################################################
# Regression: Neo4j Browser HTTP endpoint must respond on 7474
###############################################################################

BROWSER_OK=0
HTTP_CODE=000
for i in $(seq 1 10); do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:7474/ 2>/dev/null || echo 000)
    if [ "$HTTP_CODE" = "200" ]; then
        BROWSER_OK=1
        break
    fi
    sleep 3
done
if [ "$BROWSER_OK" = "1" ]; then
    record_reg neo4j_browser_7474 1 "Neo4j Browser reachable on 7474"
else
    record_reg neo4j_browser_7474 0 "Neo4j Browser not reachable on 7474 (last HTTP $HTTP_CODE)"
fi

###############################################################################
# PoC (runtime): TCP 1337 must not be LISTENING.
# /proc/net/tcp{,6}: local_address field is IP:PORT in hex; 1337 == 0x0539;
# connection state 0A == TCP_LISTEN.
###############################################################################

port_1337_listening() {
    awk '$2 ~ /:0539$/ && $4 == "0A" {found=1} END {exit !found}' \
        /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

if [ "$BROWSER_OK" = "1" ]; then
    if port_1337_listening; then
        record_poc shell_server_port_1337_unbound 0 \
            "TCP 1337 is LISTENING - the RMI Shell Server is still active"
    else
        record_poc shell_server_port_1337_unbound 1
    fi
else
    # neo4j is not serving at all, so "1337 is not listening" is what a DEAD
    # database looks like, not what a disabled shell server looks like. The PoC
    # is left UNRECORDED rather than credited.
    echo "  [SKIP] (poc) shell_server_port_1337_unbound: neo4j not serving on 7474"
fi

verify_finish
