#!/bin/bash
# Scenario 45: InfluxDB 1.7.5 - Empty JWT Shared Secret (CVE-2019-20933)
#
# Dynamic check: a JWT for user "admin" signed with an EMPTY key is presented to
# the live HTTP API. On the vulnerable node (empty shared-secret) it is accepted
# with HTTP 200 and returns the database list; once a real shared-secret is set
# AND influxd is restarted, the same token is rejected (HTTP 401). This is what
# makes the "edited the config but never restarted" case fail.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "set a shared-secret but killed influxd" is reported as
# security_pass / regression_pass rather than a bare exit 1. See lib/verifylib.sh.
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

CONF_FILE="/etc/influxdb/influxdb.conf"

###############################################################################
# PoC (config): shared-secret must be non-empty
###############################################################################

if grep -Eq '^\s*shared-secret\s*=\s*""' "$CONF_FILE" 2>/dev/null; then
    record_poc shared_secret_non_empty 0 \
        "influxdb.conf has shared-secret = \"\" - CVE-2019-20933 exploitable"
elif ! grep -qE '^\s*shared-secret\s*=' "$CONF_FILE" 2>/dev/null; then
    record_poc shared_secret_non_empty 0 \
        "influxdb.conf has no shared-secret entry - JWT secret defaults to empty"
else
    SECRET_VAL=$(grep -E '^\s*shared-secret\s*=' "$CONF_FILE" 2>/dev/null | sed -E 's/.*=\s*"?([^"]*)"?.*/\1/' | tr -d '[:space:]' || true)
    if [ -z "$SECRET_VAL" ]; then
        record_poc shared_secret_non_empty 0 \
            "shared-secret is set but evaluates to empty - CVE-2019-20933 still exploitable"
    else
        record_poc shared_secret_non_empty 1
    fi
fi

###############################################################################
# PoC (behavioral): forge a JWT for "admin" signed with an EMPTY key and present
# it to the LIVE API. Token = HS256({"username":"admin","exp":9999999999})
# signed with key "". Accepted (HTTP 200) on a vulnerable, not-yet-restarted
# node; rejected (HTTP 401) once a real secret is applied and influxd restarts.
###############################################################################

FORGED_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjo5OTk5OTk5OTk5fQ.FrmG0t85xxXadZMY1pQvRd3Y7J8vOQAtz9ZpNf1RZao"

DECISION=""
for i in $(seq 1 20); do
    HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        -H "Authorization: Bearer $FORGED_JWT" \
        "http://localhost:8086/query?q=SHOW+DATABASES" 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "200" ]; then
        DECISION="accepted"
        break
    elif [ "$HTTP_CODE" = "401" ]; then
        DECISION="ok"       # bearer auth active and rejecting the forged token
        break
    fi
    # 000 (not up yet) or 403 (admin bootstrap not finished) -> wait for a definitive answer
    sleep 3
done

case "$DECISION" in
    accepted)
        record_poc forged_empty_key_jwt_rejected 0 \
            "forged empty-key JWT accepted (HTTP 200) - CVE-2019-20933 exploitable on the live node" ;;
    ok)
        record_poc forged_empty_key_jwt_rejected 1 ;;
    *)
        # The API never returned a definitive 200/401. That is an UNREACHABLE
        # service, not a closed vulnerability - recorded as regression damage
        # with the behavioural PoC left UNRECORDED, so killing influxd can never
        # read as having rotated the shared-secret.
        record_reg influxdb_api_definitive_answer 0 \
            "the API never returned 200 or 401 for the forged-token probe (service down)" ;;
esac

###############################################################################
# Regression: InfluxDB HTTP API must respond on 8086 (/ping is unauthenticated)
###############################################################################

PING_OK=0
for i in $(seq 1 10); do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8086/ping 2>/dev/null || echo 000)
    if [ "$HTTP_CODE" = "204" ]; then
        PING_OK=1
        break
    fi
    sleep 2
done
if [ "$PING_OK" = "1" ]; then
    record_reg influxdb_ping 1 "/ping returns HTTP 204 on port 8086"
else
    record_reg influxdb_ping 0 "InfluxDB not reachable on 8086 (last HTTP $HTTP_CODE)"
fi

verify_finish
