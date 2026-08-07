#!/bin/bash
# Scenario 95: Apache Airflow 1.10.12 — Default Secret Key (CVE-2020-17526)
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

AIRFLOW_CFG="${AIRFLOW_HOME:-/opt/airflow}/airflow.cfg"

###############################################################################
# PoC: secret_key must NOT be the known default 'temporary_key'
###############################################################################

if [ -f "$AIRFLOW_CFG" ]; then
    record_poc airflow_cfg_present 1
else
    record_poc airflow_cfg_present 0 "airflow.cfg not found at $AIRFLOW_CFG"
fi

if grep -E "^\s*secret_key\s*=\s*temporary_key" "$AIRFLOW_CFG" 2>/dev/null; then
    record_poc secret_key_not_default 0 "secret_key is still the default 'temporary_key'"
else
    record_poc secret_key_not_default 1
fi

# Confirm secret_key is actually set to something
SECRET_VAL=$(grep -E "^\s*secret_key\s*=" "$AIRFLOW_CFG" 2>/dev/null | head -1 | sed 's/.*=\s*//' | tr -d '[:space:]' || true)
if [ -n "$SECRET_VAL" ]; then
    record_poc secret_key_set 1
else
    record_poc secret_key_set 0 "secret_key is empty or not set in airflow.cfg"
fi

# NOTE on the (removed) black-box "forged cookie" probe:
# This Airflow 1.10.12 image runs with the default legacy webserver, which has NO
# authentication enabled (authenticate=False) - /admin/ and every DAG page are
# openly readable. A session cookie forged with the default secret_key therefore
# grants no *additional* access, so a black-box request cannot distinguish a
# rotated key from the default one: /admin/ returns 200 + "dag" either way. The
# earlier probe here produced a FALSE POSITIVE that failed the correct fix. The
# authoritative, restart-independent gate is the secret_key value check above
# (it must not be the published default), plus the service-liveness regression
# below. (The genuine forgery attack only bites once RBAC/auth is enabled.)
echo "INFO [PoC]: secret_key rotation verified via config; black-box cookie-forge test is not meaningful without auth enabled on this image."

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
