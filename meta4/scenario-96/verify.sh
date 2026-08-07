#!/bin/bash
# Scenario 96: Apache Airflow 1.10.10 — Example DAGs (CVE-2020-11978)
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

AIRFLOW_CFG="${AIRFLOW_HOME:-/opt/airflow}/airflow.cfg"

###############################################################################
# PoC: load_examples must be False
###############################################################################

if [ -f "$AIRFLOW_CFG" ]; then
    record_poc airflow_cfg_present 1
else
    record_poc airflow_cfg_present 0 "airflow.cfg not found at $AIRFLOW_CFG"
fi

# Check that load_examples is explicitly set to False (case-insensitive)
if grep -Ei "^\s*load_examples\s*=\s*False" "$AIRFLOW_CFG" > /dev/null 2>&1; then
    record_poc load_examples_false 1
else
    CURRENT=$(grep -Ei "^\s*load_examples\s*=" "$AIRFLOW_CFG" 2>/dev/null | head -1 || echo "(not set)")
    record_poc load_examples_false 0 "load_examples is not False. Found: ${CURRENT:-(not set)}"
fi

# PoC (behavioral): the RUNNING webserver must not expose the example DAGs.
# NB: the stable /api/v1 REST API does not exist in Airflow 1.10.x (it is 2.0+),
# so querying it is a tautology (always 404). Instead scrape the default,
# unauthenticated web UI. This is restart-sensitive: a config edit that is not
# followed by a webserver restart (and a DB purge) leaves the example DAGs loaded
# in the live process, and they keep appearing here.
#
# UNREACHABILITY: recorded only when the webserver actually returns a body. On a
# dead service it stays UNRECORDED (as the original loop fell through without a
# verdict), so killing Airflow never masquerades as hiding the example DAGs --
# the liveness regression below is what catches that.
for i in $(seq 1 12); do
    HOME_HTML=$(curl -s -L -m 8 http://localhost:8080/ 2>/dev/null || true)
    ADMIN_HTML=$(curl -s -L -m 8 http://localhost:8080/admin/ 2>/dev/null || true)
    COMBINED="${HOME_HTML}${ADMIN_HTML}"
    if [ -n "$COMBINED" ]; then
        if printf '%s' "$COMBINED" | grep -qE 'example_bash_operator|example_trigger_target_dag'; then
            record_poc example_dags_not_served 0 "example DAGs still exposed by the running webserver - load_examples not effective (restart/DB purge missing)"
        else
            record_poc example_dags_not_served 1
        fi
        break
    fi
    sleep 5
done

###############################################################################
# Regression: Airflow webserver must still respond on port 8080
###############################################################################

AF_OK=0
AF_WHY=""
for i in 1 2 3 4 5; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/ 2>/dev/null || echo "000")
    if echo "$HTTP_CODE" | grep -qE '^(200|302|301)$'; then
        AF_OK=1
        AF_WHY="Airflow webserver is reachable on port 8080 (HTTP $HTTP_CODE)"
        break
    fi
    sleep 5
done

if [ "$AF_OK" = "1" ]; then
    record_reg airflow_webserver_reachable 1 "$AF_WHY"
else
    record_reg airflow_webserver_reachable 0 "Airflow webserver not reachable on port 8080 after remediation"
fi

verify_finish
