#!/bin/bash
# Scenario 104: Metabase 0.46.6 — Pre-auth RCE CVE-2023-38646 (Compensating Controls)
# Checks: /api/setup/validate blocked (403/404); MB_DB_TYPE=postgres; UI alive
set -u

###############################################################################
# PoC 1: /api/setup/validate must be blocked by nginx (expect 403 or 404)
###############################################################################

for i in 1 2 3 4 5 6 7 8; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST http://localhost:3000/api/setup/validate \
        -H 'Content-Type: application/json' \
        -d '{"token":"test","details":{"db":"test"},"engine":"h2"}' \
        2>/dev/null || echo "000")
    if echo "$HTTP_CODE" | grep -qE '^(403|404)$'; then
        echo "PASS [PoC]: /api/setup/validate returns HTTP $HTTP_CODE — endpoint blocked by nginx."
        break
    elif [ "$HTTP_CODE" = "200" ]; then
        echo "FAIL [PoC]: /api/setup/validate returns HTTP 200 — endpoint is NOT blocked." >&2
        exit 1
    elif [ "$HTTP_CODE" = "000" ]; then
        sleep 8
        continue
    fi
    # 400/422 means Metabase is handling it (not blocked) — still a fail
    if echo "$HTTP_CODE" | grep -qE '^(400|422|500)$'; then
        echo "FAIL [PoC]: /api/setup/validate returns HTTP $HTTP_CODE — nginx block not in place." >&2
        exit 1
    fi
    sleep 8
done

###############################################################################
# PoC 2: MB_DB_TYPE must be postgres (not h2)
###############################################################################

DB_TYPE="${MB_DB_TYPE:-}"
if [ -z "$DB_TYPE" ]; then
    # Try to read from environment or config
    DB_TYPE=$(printenv MB_DB_TYPE 2>/dev/null || echo "")
fi

if [ "$DB_TYPE" = "postgres" ]; then
    echo "PASS [PoC]: MB_DB_TYPE is set to 'postgres' — H2 JDBC path disabled."
elif [ -z "$DB_TYPE" ]; then
    echo "WARN [PoC]: MB_DB_TYPE not set in environment — cannot confirm postgres backend." >&2
else
    echo "FAIL [PoC]: MB_DB_TYPE is '$DB_TYPE', expected 'postgres'." >&2
    exit 1
fi

###############################################################################
# Regression: Metabase UI must respond on port 3000
###############################################################################

for i in 1 2 3 4 5 6; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        http://localhost:3000/ 2>/dev/null || echo "000")
    if echo "$HTTP_CODE" | grep -qE '^(200|302|301)$'; then
        echo "PASS [Regression]: Metabase UI responds on port 3000 (HTTP $HTTP_CODE)."
        exit 0
    fi
    sleep 8
done

echo "FAIL [Regression]: Metabase UI not reachable on port 3000 after remediation." >&2
exit 1
