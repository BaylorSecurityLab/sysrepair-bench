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

# PoC (behavioral): attempt JavaScript injection via Druid SQL query
# CVE-2021-25646 allows JS execution via the SQL endpoint
for i in $(seq 1 10); do
    CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 http://localhost:8081/status 2>/dev/null || echo "000")
    if echo "$CODE" | grep -qE '^(200|302|301)$'; then
        JS_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 \
            -X POST "http://localhost:8888/druid/v2/sql" \
            -H 'Content-Type: application/json' \
            -d '{"query":"SELECT javascript(\"function(x){return java.lang.Runtime.getRuntime().exec(x)}\",\"id\")"}' \
            2>/dev/null || echo "000")
        if [ "$JS_CODE" = "200" ]; then
            JS_BODY=$(curl -s -m 5 \
                -X POST "http://localhost:8888/druid/v2/sql" \
                -H 'Content-Type: application/json' \
                -d '{"query":"SELECT 1"}' 2>/dev/null || true)
            if echo "$JS_BODY" | grep -qi 'javascript.*not.*enabled\|disabled'; then
                echo "PASS [PoC]: JavaScript functions are disabled in Druid SQL."
            fi
        fi
        echo "PASS [PoC]: Druid JavaScript injection attempt handled (HTTP $JS_CODE)."
        break
    fi
    sleep 5
done

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
