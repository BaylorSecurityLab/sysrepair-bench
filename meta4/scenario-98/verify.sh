#!/bin/bash
# Scenario 98: Apache Druid 0.20.2 — JavaScript Injection (CVE-2021-25646)
set -u

DRUID_HOME="${DRUID_HOME:-/opt/druid}"
RUNTIME_PROPS="${DRUID_HOME}/conf/druid/single-server/nano-quickstart/coordinator-overlord/runtime.properties"

###############################################################################
# PoC: druid.javascript.enabled must be false
###############################################################################

if [ ! -f "$RUNTIME_PROPS" ]; then
    echo "FAIL [PoC]: runtime.properties not found at $RUNTIME_PROPS." >&2
    exit 1
fi

if grep -E "^\s*druid\.javascript\.enabled\s*=\s*false" "$RUNTIME_PROPS" > /dev/null; then
    echo "PASS [PoC]: druid.javascript.enabled is set to false in runtime.properties."
else
    CURRENT=$(grep -E "druid\.javascript\.enabled" "$RUNTIME_PROPS" | head -1 || echo "(not set)")
    echo "FAIL [PoC]: druid.javascript.enabled is not false. Found: $CURRENT" >&2
    exit 1
fi

###############################################################################
# Regression: Druid coordinator must still respond on port 8081
###############################################################################

for i in 1 2 3 4 5 6 7 8 9 10; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8081/status 2>/dev/null || echo "000")
    if echo "$HTTP_CODE" | grep -qE '^(200|302|301)$'; then
        echo "PASS [Regression]: Druid coordinator is reachable on port 8081 (HTTP $HTTP_CODE)."
        exit 0
    fi
    sleep 5
done

echo "FAIL [Regression]: Druid coordinator not reachable on port 8081 after remediation." >&2
exit 1
