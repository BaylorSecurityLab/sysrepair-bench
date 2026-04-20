#!/bin/bash
# Scenario 96: Apache Airflow 1.10.10 — Example DAGs (CVE-2020-11978)
set -u

AIRFLOW_CFG="${AIRFLOW_HOME:-/opt/airflow}/airflow.cfg"

###############################################################################
# PoC: load_examples must be False
###############################################################################

if [ ! -f "$AIRFLOW_CFG" ]; then
    echo "FAIL [PoC]: airflow.cfg not found at $AIRFLOW_CFG." >&2
    exit 1
fi

# Check that load_examples is explicitly set to False (case-insensitive)
if grep -Ei "^\s*load_examples\s*=\s*False" "$AIRFLOW_CFG" > /dev/null; then
    echo "PASS [PoC]: load_examples is set to False in airflow.cfg."
else
    CURRENT=$(grep -Ei "^\s*load_examples\s*=" "$AIRFLOW_CFG" | head -1 || echo "(not set)")
    echo "FAIL [PoC]: load_examples is not False. Found: $CURRENT" >&2
    exit 1
fi

# PoC (behavioral): verify example_bash_operator DAG is not available
# CVE-2020-11978 exploits the example DAG; if load_examples=False, it should not exist
for i in $(seq 1 10); do
    CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 http://localhost:8080/ 2>/dev/null || echo "000")
    if echo "$CODE" | grep -qE '^(200|302|301)$'; then
        DAG_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 \
            "http://localhost:8080/api/v1/dags/example_bash_operator" 2>/dev/null || echo "000")
        if [ "$DAG_CODE" = "200" ]; then
            echo "FAIL [PoC]: example_bash_operator DAG is still present — load_examples may not be effective." >&2
            exit 1
        fi
        echo "PASS [PoC]: example_bash_operator DAG not found (HTTP $DAG_CODE)."
        break
    fi
    sleep 5
done

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
