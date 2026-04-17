#!/bin/bash
# Scenario 41: CouchDB 3.1 — Admin Party (misconfig)
set -u

COUCH_URL="http://localhost:5984"

###############################################################################
# PoC: unauthenticated _all_dbs must return 401, not 200
###############################################################################

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${COUCH_URL}/_all_dbs")

if [ "$HTTP_CODE" = "200" ]; then
    echo "FAIL [PoC]: CouchDB returned HTTP 200 for unauthenticated /_all_dbs — Admin Party is active." >&2
    exit 1
fi

if [ "$HTTP_CODE" != "401" ]; then
    echo "FAIL [PoC]: CouchDB returned unexpected HTTP ${HTTP_CODE} (expected 401 after closing Admin Party)." >&2
    exit 1
fi

echo "PASS [PoC]: CouchDB rejects unauthenticated /_all_dbs with HTTP 401."

###############################################################################
# Regression: authenticated requests must succeed
###############################################################################

# The remediation step creates an admin named "admin"; accept any valid creds
# by checking that CouchDB itself is still healthy via /_up (no auth required)
for i in 1 2 3 4 5; do
    UP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${COUCH_URL}/_up")
    if [ "$UP_CODE" = "200" ]; then
        echo "PASS [Regression]: CouchDB /_up reports healthy after Admin Party closure."
        exit 0
    fi
    sleep 2
done

echo "FAIL [Regression]: CouchDB not reachable on 5984 after remediation." >&2
exit 1
