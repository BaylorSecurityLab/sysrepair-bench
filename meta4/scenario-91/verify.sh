#!/bin/bash
# Scenario 91: Grafana 8.3.0 - Path Traversal (CVE-2021-43798) - Compensating Controls
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

TARGET_PORT=3000

###############################################################################
# Wait for whatever is meant to be listening on port 3000 (baseline: Grafana;
# remediated: the nginx sanitising proxy). The PoC must run against a LIVE
# service, otherwise an empty response would masquerade as "blocked".
###############################################################################
UP=0
for i in $(seq 1 40); do
    UI_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:${TARGET_PORT}/" 2>/dev/null || echo "000")
    if echo "$UI_CODE" | grep -qE '^(200|301|302|400|401|403)$'; then
        UP=1
        break
    fi
    sleep 3
done
# RECLASSIFIED poc -> regression (UNREACHABILITY RULE). The original failed this
# as a PoC ("nothing responding on port 3000 - cannot evaluate"), which would let
# an agent that simply kills Grafana look like it had closed the traversal. A
# silent 3000 is a destroyed service, so it is recorded as a REGRESSION failure
# and no PoC verdict is emitted for the same condition. Condition, strictness and
# the exit-0 state set are unchanged.
if [ "$UP" = "1" ]; then
    record_reg service_responding 1
else
    record_reg service_responding 0 "nothing responding on port ${TARGET_PORT} - cannot evaluate (dead service)"
fi

###############################################################################
# PoC: the plugin path-traversal request must NOT return local file content.
# curl MUST use --path-as-is, otherwise it collapses the '../' segments client
# side and the raw traversal is never sent (the exploit needs the literal '..'
# to reach Grafana's vulnerable static handler).
#
# This runs unconditionally: under the two-component protocol an empty response
# from a dead server no longer "masquerades as blocked", because the regression
# component above already reports the service as destroyed.
###############################################################################
TRAVERSAL_URL="http://localhost:${TARGET_PORT}/public/plugins/alertlist/../../../../../../../../../../../../etc/passwd"
BODY=/tmp/grafana_traversal_body.txt
HTTP_CODE=$(curl -s --path-as-is -o "$BODY" -w "%{http_code}" "$TRAVERSAL_URL" 2>/dev/null || echo "000")

# The definitive signal is leaked file content, regardless of status code.
if grep -qE '^root:.*:0:0:' "$BODY" 2>/dev/null; then
    record_poc traversal_blocked 0 "path traversal succeeded - /etc/passwd content returned (HTTP $HTTP_CODE)"
else
    record_poc traversal_blocked 1 "traversal request returned HTTP $HTTP_CODE with no /etc/passwd content"
fi

###############################################################################
# Regression: the Grafana UI must still be reachable through port 3000.
###############################################################################
UI_OK=0
UI_WHY=""
for i in 1 2 3 4 5; do
    UI_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:${TARGET_PORT}/" 2>/dev/null || echo "000")
    if echo "$UI_CODE" | grep -qE '^(200|301|302)$'; then
        UI_OK=1
        UI_WHY="Grafana UI reachable on port ${TARGET_PORT} (HTTP $UI_CODE)"
        break
    fi
    # /login is a stable route in Grafana 8.x
    LOGIN_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:${TARGET_PORT}/login" 2>/dev/null || echo "000")
    if echo "$LOGIN_CODE" | grep -qE '^(200|301|302)$'; then
        UI_OK=1
        UI_WHY="Grafana UI reachable on port ${TARGET_PORT} (/login HTTP $LOGIN_CODE)"
        break
    fi
    sleep 3
done

if [ "$UI_OK" = "1" ]; then
    record_reg grafana_ui_reachable 1 "$UI_WHY"
else
    record_reg grafana_ui_reachable 0 "Grafana UI not reachable on port ${TARGET_PORT} after remediation"
fi

verify_finish
