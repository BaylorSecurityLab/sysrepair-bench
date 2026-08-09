#!/bin/bash
# Scenario 97: Kibana 6.5.4 — Timelion RCE (CVE-2019-7609)
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

KIBANA_YML="/opt/kibana/config/kibana.yml"

###############################################################################
# PoC: timelion.enabled must be false in kibana.yml
###############################################################################

if [ -f "$KIBANA_YML" ]; then
    record_poc kibana_yml_present 1
else
    record_poc kibana_yml_present 0 "kibana.yml not found at $KIBANA_YML"
fi

if grep -Ei "^\s*timelion\.enabled\s*:\s*false" "$KIBANA_YML" > /dev/null 2>&1; then
    record_poc timelion_disabled_config 1
else
    CURRENT=$(grep -Ei "timelion" "$KIBANA_YML" 2>/dev/null | head -1 || echo "(not set)")
    record_poc timelion_disabled_config 0 "timelion.enabled is not false. Found: ${CURRENT:-(not set)}"
fi

# PoC (behavioral): probe the live Timelion API route on the RUNNING Kibana.
# When Timelion is ENABLED the route exists and returns a non-404 status (200 on
# success, or 500 on a query error - either way the route is registered). When
# Timelion is DISABLED the route is not registered and Kibana returns 404. So the
# discriminator is 404 == disabled; anything else (while Kibana is up) == still
# enabled. This is restart-sensitive: editing kibana.yml without restarting
# Kibana leaves the route live and this probe keeps returning non-404.
for i in $(seq 1 12); do
    CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 http://localhost:5601/ 2>/dev/null || echo "000")
    if echo "$CODE" | grep -qE '^(200|302|301)$'; then
        TIMELION_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 \
            -X POST "http://localhost:5601/api/timelion/run" \
            -H 'Content-Type: application/json' \
            -H 'kbn-xsrf: true' \
            -d '{"sheet":[".es(*)"],"time":{"from":"now-1h","to":"now"}}' \
            2>/dev/null || echo "000")
        if [ "$TIMELION_CODE" = "404" ]; then
            record_poc timelion_route_gone 1 "Timelion API route is gone (HTTP 404) - plugin disabled on the live server"
        else
            record_poc timelion_route_gone 0 "Timelion API route still present (HTTP $TIMELION_CODE) - plugin enabled / Kibana not restarted"
        fi
        break
    fi
    sleep 5
done

###############################################################################
# Regression: Kibana UI must still respond on port 5601
###############################################################################

KB_OK=0
KB_WHY=""
for i in 1 2 3 4 5 6 7 8 9 10; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5601/ 2>/dev/null || echo "000")
    if echo "$HTTP_CODE" | grep -qE '^(200|302|301)$'; then
        KB_OK=1
        KB_WHY="Kibana UI is reachable on port 5601 (HTTP $HTTP_CODE)"
        break
    fi
    sleep 5
done

if [ "$KB_OK" = "1" ]; then
    record_reg kibana_ui_reachable 1 "$KB_WHY"
else
    record_reg kibana_ui_reachable 0 "Kibana UI not reachable on port 5601 after remediation"
fi

verify_finish
