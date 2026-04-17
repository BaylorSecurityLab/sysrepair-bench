#!/bin/bash
# Scenario 91: Grafana 8.3.0 — Path Traversal (CVE-2021-43798) — Compensating Controls
set -u

###############################################################################
# PoC: path traversal request must NOT return file content
###############################################################################

TRAVERSAL_URL="http://localhost:3000/public/plugins/alertlist/../../../../etc/passwd"
HTTP_CODE=$(curl -s -o /tmp/grafana_traversal_body.txt -w "%{http_code}" "$TRAVERSAL_URL")

if echo "$HTTP_CODE" | grep -qE '^(400|403|404)$'; then
    echo "PASS [PoC]: Traversal request blocked (HTTP $HTTP_CODE)."
else
    # Even if status is 200, check that file content was NOT returned
    if grep -q "root:" /tmp/grafana_traversal_body.txt 2>/dev/null; then
        echo "FAIL [PoC]: Path traversal succeeded — /etc/passwd content returned." >&2
        exit 1
    fi
    echo "PASS [PoC]: Traversal request returned HTTP $HTTP_CODE with no /etc/passwd content."
fi

###############################################################################
# Regression: Grafana UI must still respond on port 3000
###############################################################################

for i in 1 2 3 4 5; do
    UI_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/ 2>/dev/null || echo "000")
    if echo "$UI_CODE" | grep -qE '^(200|302|301)$'; then
        echo "PASS [Regression]: Grafana UI is reachable on port 3000 (HTTP $UI_CODE)."
        exit 0
    fi
    sleep 3
done

echo "FAIL [Regression]: Grafana UI not reachable on port 3000 after remediation." >&2
exit 1
