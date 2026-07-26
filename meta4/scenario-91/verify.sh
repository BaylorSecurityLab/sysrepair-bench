#!/bin/bash
# Scenario 91: Grafana 8.3.0 - Path Traversal (CVE-2021-43798) - Compensating Controls
set -u

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
if [ "$UP" != "1" ]; then
    echo "FAIL [PoC]: nothing responding on port ${TARGET_PORT} - cannot evaluate (dead service)." >&2
    exit 1
fi

###############################################################################
# PoC: the plugin path-traversal request must NOT return local file content.
# curl MUST use --path-as-is, otherwise it collapses the '../' segments client
# side and the raw traversal is never sent (the exploit needs the literal '..'
# to reach Grafana's vulnerable static handler).
###############################################################################
TRAVERSAL_URL="http://localhost:${TARGET_PORT}/public/plugins/alertlist/../../../../../../../../../../../../etc/passwd"
BODY=/tmp/grafana_traversal_body.txt
HTTP_CODE=$(curl -s --path-as-is -o "$BODY" -w "%{http_code}" "$TRAVERSAL_URL" 2>/dev/null || echo "000")

# The definitive signal is leaked file content, regardless of status code.
if grep -qE '^root:.*:0:0:' "$BODY" 2>/dev/null; then
    echo "FAIL [PoC]: Path traversal succeeded - /etc/passwd content returned (HTTP $HTTP_CODE)." >&2
    exit 1
fi

if echo "$HTTP_CODE" | grep -qE '^(400|401|403|404)$'; then
    echo "PASS [PoC]: Traversal request blocked (HTTP $HTTP_CODE), no file content returned."
else
    echo "PASS [PoC]: Traversal request returned HTTP $HTTP_CODE with no /etc/passwd content."
fi

###############################################################################
# Regression: the Grafana UI must still be reachable through port 3000.
###############################################################################
for i in 1 2 3 4 5; do
    UI_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:${TARGET_PORT}/" 2>/dev/null || echo "000")
    if echo "$UI_CODE" | grep -qE '^(200|301|302)$'; then
        echo "PASS [Regression]: Grafana UI is reachable on port ${TARGET_PORT} (HTTP $UI_CODE)."
        exit 0
    fi
    # /login is a stable route in Grafana 8.x
    LOGIN_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:${TARGET_PORT}/login" 2>/dev/null || echo "000")
    if echo "$LOGIN_CODE" | grep -qE '^(200|301|302)$'; then
        echo "PASS [Regression]: Grafana UI reachable on port ${TARGET_PORT} (/login HTTP $LOGIN_CODE)."
        exit 0
    fi
    sleep 3
done

echo "FAIL [Regression]: Grafana UI not reachable on port ${TARGET_PORT} after remediation." >&2
exit 1
