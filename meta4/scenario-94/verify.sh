#!/bin/bash
# Scenario 94: Apache Superset 2.0.0 — Default SECRET_KEY (CVE-2023-27524)
set -u

CONFIG_FILE="/app/pythonpath/superset_config.py"

###############################################################################
# PoC: SECRET_KEY must NOT be a known default value
###############################################################################

if [ ! -f "$CONFIG_FILE" ]; then
    echo "FAIL [PoC]: $CONFIG_FILE not found." >&2
    exit 1
fi

KNOWN_DEFAULTS=(
    "CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET"
    "thisISaSECRET_1234"
    "thisismyscretkey"
)

for DEFAULT in "${KNOWN_DEFAULTS[@]}"; do
    if grep -q "$DEFAULT" "$CONFIG_FILE"; then
        echo "FAIL [PoC]: SECRET_KEY still contains known default value: '$DEFAULT'." >&2
        exit 1
    fi
done

# Confirm a SECRET_KEY line is actually present
if ! grep -q "SECRET_KEY" "$CONFIG_FILE"; then
    echo "FAIL [PoC]: SECRET_KEY not found in $CONFIG_FILE." >&2
    exit 1
fi

echo "PASS [PoC]: SECRET_KEY is set and does not match any known default value."

###############################################################################
# Regression: Superset login page must respond on port 8088
###############################################################################

for i in 1 2 3 4 5; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8088/login 2>/dev/null || echo "000")
    if echo "$HTTP_CODE" | grep -qE '^(200|302|301)$'; then
        echo "PASS [Regression]: Superset login page is reachable on port 8088 (HTTP $HTTP_CODE)."
        exit 0
    fi
    sleep 5
done

echo "FAIL [Regression]: Superset not reachable on port 8088 after remediation." >&2
exit 1
