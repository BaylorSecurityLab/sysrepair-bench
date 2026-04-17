#!/bin/bash
# Scenario 95: Apache Airflow 1.10.12 — Default Secret Key (CVE-2020-17526)
set -u

AIRFLOW_CFG="${AIRFLOW_HOME:-/opt/airflow}/airflow.cfg"

###############################################################################
# PoC: secret_key must NOT be the known default 'temporary_key'
###############################################################################

if [ ! -f "$AIRFLOW_CFG" ]; then
    echo "FAIL [PoC]: airflow.cfg not found at $AIRFLOW_CFG." >&2
    exit 1
fi

if grep -E "^\s*secret_key\s*=\s*temporary_key" "$AIRFLOW_CFG"; then
    echo "FAIL [PoC]: secret_key is still the default 'temporary_key'." >&2
    exit 1
fi

# Confirm secret_key is actually set to something
SECRET_VAL=$(grep -E "^\s*secret_key\s*=" "$AIRFLOW_CFG" | head -1 | sed 's/.*=\s*//' | tr -d '[:space:]')
if [ -z "$SECRET_VAL" ]; then
    echo "FAIL [PoC]: secret_key is empty or not set in airflow.cfg." >&2
    exit 1
fi

echo "PASS [PoC]: secret_key is set to a non-default value."

###############################################################################
# Regression: Airflow webserver must still respond on port 8080
###############################################################################

for i in 1 2 3 4 5; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/ 2>/dev/null || echo "000")
    if echo "$HTTP_CODE" | grep -qE '^(200|302|301)$'; then
        echo "PASS [Regression]: Airflow webserver is reachable on port 8080 (HTTP $HTTP_CODE)."
        exit 0
    fi
    sleep 5
done

echo "FAIL [Regression]: Airflow webserver not reachable on port 8080 after remediation." >&2
exit 1
