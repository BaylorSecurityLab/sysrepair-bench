#!/bin/bash
# Scenario 45: InfluxDB 1.7.5 - Empty JWT Shared Secret (CVE-2019-20933)
#
# Dynamic check: a JWT for user "admin" signed with an EMPTY key is presented to
# the live HTTP API. On the vulnerable node (empty shared-secret) it is accepted
# with HTTP 200 and returns the database list; once a real shared-secret is set
# AND influxd is restarted, the same token is rejected (HTTP 401). This is what
# makes the "edited the config but never restarted" case fail.
set -u

CONF_FILE="/etc/influxdb/influxdb.conf"

###############################################################################
# PoC (config): shared-secret must be non-empty
###############################################################################

if grep -Eq '^\s*shared-secret\s*=\s*""' "$CONF_FILE" 2>/dev/null; then
    echo "FAIL [PoC]: influxdb.conf has shared-secret = \"\" - CVE-2019-20933 exploitable." >&2
    exit 1
fi

if ! grep -qE '^\s*shared-secret\s*=' "$CONF_FILE" 2>/dev/null; then
    echo "FAIL [PoC]: influxdb.conf has no shared-secret entry - JWT secret defaults to empty." >&2
    exit 1
fi

SECRET_VAL=$(grep -E '^\s*shared-secret\s*=' "$CONF_FILE" | sed -E 's/.*=\s*"?([^"]*)"?.*/\1/' | tr -d '[:space:]')
if [ -z "$SECRET_VAL" ]; then
    echo "FAIL [PoC]: shared-secret is set but evaluates to empty - CVE-2019-20933 still exploitable." >&2
    exit 1
fi

echo "PASS [PoC config]: shared-secret is non-empty."

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
        echo "FAIL [PoC]: Forged empty-key JWT accepted (HTTP 200) - CVE-2019-20933 exploitable on the live node." >&2
        exit 1
    elif [ "$HTTP_CODE" = "401" ]; then
        DECISION="ok"       # bearer auth active and rejecting the forged token
        break
    fi
    # 000 (not up yet) or 403 (admin bootstrap not finished) -> wait for a definitive answer
    sleep 3
done

if [ "$DECISION" != "ok" ]; then
    echo "FAIL [PoC]: could not get a definitive answer from the API (never returned 200 or 401)." >&2
    exit 1
fi
echo "PASS [PoC behavioral]: forged empty-key JWT rejected (HTTP 401)."

###############################################################################
# Regression: InfluxDB HTTP API must respond on 8086 (/ping is unauthenticated)
###############################################################################

for i in $(seq 1 10); do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8086/ping 2>/dev/null)
    if [ "$HTTP_CODE" = "204" ]; then
        echo "PASS [Regression]: InfluxDB /ping returns HTTP 204 on port 8086."
        exit 0
    fi
    sleep 2
done

echo "FAIL [Regression]: InfluxDB not reachable on 8086 after remediation." >&2
exit 1
