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

# PoC (behavioral): the RUNNING webserver must not expose the example DAGs.
# NB: the stable /api/v1 REST API does not exist in Airflow 1.10.x (it is 2.0+),
# so querying it is a tautology (always 404). Instead scrape the default,
# unauthenticated web UI. This is restart-sensitive: a config edit that is not
# followed by a webserver restart (and a DB purge) leaves the example DAGs loaded
# in the live process, and they keep appearing here.
for i in $(seq 1 12); do
    HOME_HTML=$(curl -s -L -m 8 http://localhost:8080/ 2>/dev/null || true)
    ADMIN_HTML=$(curl -s -L -m 8 http://localhost:8080/admin/ 2>/dev/null || true)
    COMBINED="${HOME_HTML}${ADMIN_HTML}"
    if [ -n "$COMBINED" ]; then
        if printf '%s' "$COMBINED" | grep -qE 'example_bash_operator|example_trigger_target_dag'; then
            echo "FAIL [PoC]: example DAGs still exposed by the running webserver - load_examples not effective (restart/DB purge missing)." >&2
            exit 1
        fi
        echo "PASS [PoC]: example DAGs are not exposed by the running webserver."
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
