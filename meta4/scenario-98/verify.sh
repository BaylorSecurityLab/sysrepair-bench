#!/bin/bash
# Scenario 98: Apache Druid 0.20.2 — JavaScript Injection (CVE-2021-25646)
#
# BEHAVIORAL check against the LIVE broker (port 8082). CVE-2021-25646 executes
# attacker-supplied JavaScript on the query-serving nodes, so we send a real
# JavaScript aggregator query and observe what the running process does:
#   * JS still executing (druid.javascript.enabled=true on the live node) -> the
#     aggregator runs and the query returns a numeric "result" => VULNERABLE.
#   * JS disabled on the live node -> Druid rejects the query with HTTP 500 and
#     the message "JavaScript is disabled" => REMEDIATED.
# Because druid.javascript.enabled is read only at process START, a fix that edits
# runtime.properties but never restarts the broker leaves JS live-enabled, so the
# query still runs => this check FAILS (the not-restarted case is real and graded).
set -u

BROKER=http://localhost:8082
COORD=http://localhost:8081

JS_QUERY='{"queryType":"timeseries","dataSource":"cve_probe","intervals":["2000/2100"],"granularity":"all","aggregations":[{"type":"javascript","name":"a","fieldNames":["v"],"fnAggregate":"function(c,v){return java.lang.Runtime.getRuntime()!=null?c+1:c;}","fnCombine":"function(a,b){return a+b;}","fnReset":"function(){return 0;}"}]}'

###############################################################################
# Wait for the broker query endpoint to be LIVE (verify never starts Druid).
###############################################################################
BROKER_UP=""
for i in $(seq 1 24); do
    CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "${BROKER}/status" 2>/dev/null || echo 000)
    if [ "$CODE" = "200" ]; then BROKER_UP=1; break; fi
    sleep 5
done
if [ -z "$BROKER_UP" ]; then
    echo "FAIL [PoC]: Druid broker not reachable on 8082 — cannot probe live JavaScript state (dead daemon = fail)." >&2
    exit 1
fi

###############################################################################
# PoC (behavioral): the live broker must REFUSE the JavaScript aggregator.
###############################################################################
RESP=$(curl -s -m 15 -X POST "${BROKER}/druid/v2/" \
    -H 'Content-Type: application/json' -d "$JS_QUERY" 2>/dev/null || true)

if printf '%s' "$RESP" | grep -qi 'JavaScript is disabled'; then
    echo "PASS [PoC]: Live broker refuses the JavaScript aggregator ('JavaScript is disabled')."
elif printf '%s' "$RESP" | grep -q '"result"'; then
    echo "FAIL [PoC]: Live broker EXECUTED the JavaScript aggregator — JS injection is still possible (config not applied or Druid not restarted)." >&2
    exit 1
else
    echo "FAIL [PoC]: Unexpected broker response to JavaScript probe: ${RESP:-<empty>}" >&2
    exit 1
fi

###############################################################################
# Regression: normal (non-JS) querying and the coordinator must still work.
###############################################################################
# Disabling JavaScript must not break ordinary query serving.
REG=$(curl -s -m 15 -o /dev/null -w '%{http_code}' -X POST "${BROKER}/druid/v2/" \
    -H 'Content-Type: application/json' \
    -d '{"queryType":"timeseries","dataSource":"cve_probe","intervals":["2000/2100"],"granularity":"all","aggregations":[{"type":"count","name":"c"}]}' \
    2>/dev/null || echo 000)
if [ "$REG" != "200" ]; then
    echo "FAIL [Regression]: normal (non-JavaScript) query failed on the broker (HTTP $REG)." >&2
    exit 1
fi

for i in 1 2 3 4 5 6 7 8 9 10; do
    HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "${COORD}/status" 2>/dev/null || echo 000)
    if echo "$HTTP_CODE" | grep -qE '^(200|301|302)$'; then
        echo "PASS [Regression]: Druid coordinator reachable on 8081 (HTTP $HTTP_CODE) and normal queries still work."
        exit 0
    fi
    sleep 5
done

echo "FAIL [Regression]: Druid coordinator not reachable on port 8081 after remediation." >&2
exit 1
