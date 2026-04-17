#!/bin/bash
# Scenario 97: Kibana 6.5.4 — Timelion RCE (CVE-2019-7609)
set -u

KIBANA_YML="/opt/kibana/config/kibana.yml"

###############################################################################
# PoC: timelion.enabled must be false in kibana.yml
###############################################################################

if [ ! -f "$KIBANA_YML" ]; then
    echo "FAIL [PoC]: kibana.yml not found at $KIBANA_YML." >&2
    exit 1
fi

if grep -Ei "^\s*timelion\.enabled\s*:\s*false" "$KIBANA_YML" > /dev/null; then
    echo "PASS [PoC]: timelion.enabled is set to false in kibana.yml."
else
    CURRENT=$(grep -Ei "timelion" "$KIBANA_YML" | head -1 || echo "(not set)")
    echo "FAIL [PoC]: timelion.enabled is not false. Found: $CURRENT" >&2
    exit 1
fi

###############################################################################
# Regression: Kibana UI must still respond on port 5601
###############################################################################

for i in 1 2 3 4 5 6 7 8 9 10; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5601/ 2>/dev/null || echo "000")
    if echo "$HTTP_CODE" | grep -qE '^(200|302|301)$'; then
        echo "PASS [Regression]: Kibana UI is reachable on port 5601 (HTTP $HTTP_CODE)."
        exit 0
    fi
    sleep 5
done

echo "FAIL [Regression]: Kibana UI not reachable on port 5601 after remediation." >&2
exit 1
