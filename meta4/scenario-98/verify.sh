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

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

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
# RECLASSIFIED poc -> regression (UNREACHABILITY RULE). The original charged an
# unreachable broker to the PoC ("dead daemon = fail"), so an agent that simply
# killed Druid was scored on the security axis for it. A silent 8082 is a
# destroyed service: record it as a REGRESSION failure and emit no PoC verdict
# for the same condition. Condition, strictness and the exit-0 state set are
# unchanged.
if [ -n "$BROKER_UP" ]; then
    record_reg broker_responding 1
else
    record_reg broker_responding 0 "Druid broker not reachable on 8082 - cannot probe live JavaScript state"
fi

###############################################################################
# PoC (behavioral): the live broker must REFUSE the JavaScript aggregator.
###############################################################################
RESP=$(curl -s -m 15 -X POST "${BROKER}/druid/v2/" \
    -H 'Content-Type: application/json' -d "$JS_QUERY" 2>/dev/null || true)

if printf '%s' "$RESP" | grep -qi 'JavaScript is disabled'; then
    record_poc js_aggregator_refused 1 "live broker refuses the JavaScript aggregator ('JavaScript is disabled')"
elif printf '%s' "$RESP" | grep -q '"result"'; then
    record_poc js_aggregator_refused 0 "live broker EXECUTED the JavaScript aggregator - JS injection is still possible (config not applied or Druid not restarted)"
else
    record_poc js_aggregator_refused 0 "unexpected broker response to JavaScript probe: ${RESP:-<empty>}"
fi

###############################################################################
# Regression: normal (non-JS) querying and the coordinator must still work.
###############################################################################
# Disabling JavaScript must not break ordinary query serving.
REG=$(curl -s -m 15 -o /dev/null -w '%{http_code}' -X POST "${BROKER}/druid/v2/" \
    -H 'Content-Type: application/json' \
    -d '{"queryType":"timeseries","dataSource":"cve_probe","intervals":["2000/2100"],"granularity":"all","aggregations":[{"type":"count","name":"c"}]}' \
    2>/dev/null || echo 000)
if [ "$REG" = "200" ]; then
    record_reg normal_query_works 1
else
    record_reg normal_query_works 0 "normal (non-JavaScript) query failed on the broker (HTTP $REG)"
fi

CO_OK=0
CO_WHY=""
for i in 1 2 3 4 5 6 7 8 9 10; do
    HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "${COORD}/status" 2>/dev/null || echo 000)
    if echo "$HTTP_CODE" | grep -qE '^(200|301|302)$'; then
        CO_OK=1
        CO_WHY="Druid coordinator reachable on 8081 (HTTP $HTTP_CODE)"
        break
    fi
    sleep 5
done

if [ "$CO_OK" = "1" ]; then
    record_reg coordinator_reachable 1 "$CO_WHY"
else
    record_reg coordinator_reachable 0 "Druid coordinator not reachable on port 8081 after remediation"
fi

verify_finish
