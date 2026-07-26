#!/bin/bash
# Scenario 46: Neo4j 3.4 - Shell Server RMI Deserialization RCE (CVE-2021-34371)
#
# Dynamic check: confirm the RMI Shell Server listener on TCP 1337 is actually
# bound on the LIVE node. The stock image binds 1337 (verified empirically);
# disabling dbms.shell.enabled and restarting neo4j unbinds it. The listener is
# detected by parsing /proc/net/tcp{,6} - the image has no `ss`/`netstat`, so
# the original `ss -tlnp | grep :1337` silently passed even while 1337 was up.
set -u

NEO4J_CONF="/var/lib/neo4j/conf/neo4j.conf"
[ -f "$NEO4J_CONF" ] || NEO4J_CONF="/etc/neo4j/neo4j.conf"

###############################################################################
# PoC (config): Shell Server must be disabled
###############################################################################

if grep -qE '^\s*dbms\.shell\.enabled\s*=\s*true' "$NEO4J_CONF" 2>/dev/null; then
    echo "FAIL [PoC]: neo4j.conf has dbms.shell.enabled=true - CVE-2021-34371 reachable." >&2
    exit 1
fi
echo "PASS [PoC config]: dbms.shell.enabled is not true in neo4j.conf."

###############################################################################
# PoC (runtime): TCP 1337 must not be LISTENING.
# /proc/net/tcp{,6}: local_address field is IP:PORT in hex; 1337 == 0x0539;
# connection state 0A == TCP_LISTEN.
###############################################################################

port_1337_listening() {
    awk '$2 ~ /:0539$/ && $4 == "0A" {found=1} END {exit !found}' \
        /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

if port_1337_listening; then
    echo "FAIL [PoC]: TCP 1337 is LISTENING - the RMI Shell Server is still active." >&2
    exit 1
fi
echo "PASS [PoC runtime]: TCP 1337 is not listening."

###############################################################################
# Regression: Neo4j Browser HTTP endpoint must respond on 7474
###############################################################################

for i in $(seq 1 10); do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:7474/ 2>/dev/null)
    if [ "$HTTP_CODE" = "200" ]; then
        echo "PASS [Regression]: Neo4j Browser reachable on 7474."
        exit 0
    fi
    sleep 3
done

echo "FAIL [Regression]: Neo4j Browser not reachable on 7474 after remediation." >&2
exit 1
