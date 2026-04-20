#!/bin/bash
# Scenario 45: InfluxDB 1.7.6 — Empty JWT Shared Secret (CVE-2019-20933)
set -u

CONF_FILE="/etc/influxdb/influxdb.conf"

###############################################################################
# PoC: shared-secret must be non-empty
###############################################################################

# Check for empty shared-secret in config
if grep -E '^\s*shared-secret\s*=\s*""' "$CONF_FILE" 2>/dev/null; then
    echo "FAIL [PoC]: influxdb.conf has shared-secret = \"\" — CVE-2019-20933 exploitable." >&2
    exit 1
fi

# Also flag if shared-secret key is absent entirely (defaults to empty)
if ! grep -qE '^\s*shared-secret\s*=' "$CONF_FILE" 2>/dev/null; then
    echo "FAIL [PoC]: influxdb.conf has no shared-secret entry — JWT secret defaults to empty." >&2
    exit 1
fi

# Ensure the value is not blank (whitespace only)
SECRET_VAL=$(grep -E '^\s*shared-secret\s*=' "$CONF_FILE" | sed -E 's/.*=\s*"?([^"]*)"?.*/\1/' | tr -d '[:space:]')
if [ -z "$SECRET_VAL" ]; then
    echo "FAIL [PoC]: shared-secret is set but evaluates to empty — CVE-2019-20933 still exploitable." >&2
    exit 1
fi

echo "PASS [PoC]: shared-secret is non-empty — forged JWT tokens will be rejected."

# PoC (behavioral): attempt to use a forged JWT with empty secret
# Generate a JWT signed with empty key — a vulnerable InfluxDB accepts it
FORGED_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjo5OTk5OTk5OTk5fQ.QKxRnnBHnunsQ_3T2IWbIFEZT8aU7WMjsBSvP2mTjJo"
for i in 1 2 3 4 5; do
    HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        -H "Authorization: Bearer $FORGED_JWT" \
        "http://localhost:8086/query?q=SHOW+DATABASES" 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "200" ]; then
        echo "FAIL [PoC]: Forged JWT with empty secret accepted (HTTP 200) — CVE-2019-20933 still exploitable." >&2
        exit 1
    elif [ "$HTTP_CODE" != "000" ]; then
        echo "PASS [PoC]: Forged JWT rejected (HTTP $HTTP_CODE)."
        break
    fi
    sleep 2
done

###############################################################################
# Regression: InfluxDB HTTP API must respond on 8086
###############################################################################

for i in 1 2 3 4 5; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8086/ping 2>/dev/null)
    if [ "$HTTP_CODE" = "204" ]; then
        echo "PASS [Regression]: InfluxDB /ping returns HTTP 204 on port 8086."
        exit 0
    fi
    sleep 2
done

echo "FAIL [Regression]: InfluxDB not reachable on 8086 after remediation." >&2
exit 1
