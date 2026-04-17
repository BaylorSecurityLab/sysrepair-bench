#!/bin/bash
# Scenario 46: Neo4j 3.4 — Shell Server RMI Deserialization RCE (CVE-2021-34371)
set -u

NEO4J_CONF="/var/lib/neo4j/conf/neo4j.conf"
# Fallback config path used by some Neo4j 3.x images
[ -f "$NEO4J_CONF" ] || NEO4J_CONF="/etc/neo4j/neo4j.conf"

###############################################################################
# PoC: Shell Server must be disabled (config check)
###############################################################################

if grep -qE '^\s*dbms\.shell\.enabled\s*=\s*true' "$NEO4J_CONF" 2>/dev/null; then
    echo "FAIL [PoC]: neo4j.conf has dbms.shell.enabled=true — CVE-2021-34371 reachable." >&2
    exit 1
fi

echo "PASS [PoC]: dbms.shell.enabled is not true in neo4j.conf."

###############################################################################
# PoC 2: Port 1337 must not be listening
###############################################################################

if ss -tlnp | grep -q ':1337'; then
    echo "FAIL [PoC]: Port 1337 is still listening — RMI Shell Server may still be active." >&2
    exit 1
fi

echo "PASS [PoC]: Port 1337 is not listening."

###############################################################################
# Regression: Neo4j Browser HTTP endpoint must respond on 7474
###############################################################################

for i in 1 2 3 4 5 6 7 8 9 10; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:7474/ 2>/dev/null)
    if [ "$HTTP_CODE" = "200" ]; then
        echo "PASS [Regression]: Neo4j Browser reachable on 7474."
        exit 0
    fi
    sleep 3
done

echo "FAIL [Regression]: Neo4j Browser not reachable on 7474 after remediation." >&2
exit 1
