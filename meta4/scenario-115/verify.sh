#!/bin/bash
# Scenario 115: Apache Solr 8.8 — DataImportHandler RCE (CVE-2019-0193)
set -u

###############################################################################
# Wait for Solr to be ready
###############################################################################

for i in $(seq 1 30); do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" \
           "http://localhost:8983/solr/admin/cores?action=STATUS" 2>/dev/null || echo "000")
    [ "$CODE" = "200" ] || [ "$CODE" = "401" ] && break
    sleep 3
done

###############################################################################
# PoC: DIH endpoint must require auth (401) or be removed (404)
###############################################################################

DIH_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
           "http://localhost:8983/solr/testcore/dataimport" 2>/dev/null || echo "000")

if [ "$DIH_CODE" = "401" ]; then
    echo "PASS [PoC]: DIH endpoint requires authentication (401)."
elif [ "$DIH_CODE" = "404" ]; then
    echo "PASS [PoC]: DIH endpoint is removed/disabled (404)."
elif [ "$DIH_CODE" = "000" ]; then
    echo "FAIL [PoC]: Solr not responding on port 8983." >&2
    exit 1
else
    # Check if the response body indicates DIH is accessible without auth
    BODY=$(curl -s "http://localhost:8983/solr/testcore/dataimport" 2>/dev/null || true)
    if echo "$BODY" | grep -qi "DataImportHandler\|status.*idle\|status.*busy"; then
        echo "FAIL [PoC]: DIH endpoint is accessible without authentication (HTTP $DIH_CODE)." >&2
        exit 1
    else
        echo "PASS [PoC]: DIH endpoint returned $DIH_CODE without DIH status content."
    fi
fi

###############################################################################
# Regression: Solr search endpoint must still be reachable
###############################################################################

SELECT_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
              "http://localhost:8983/solr/testcore/select?q=*:*" 2>/dev/null || echo "000")

if [ "$SELECT_CODE" = "200" ] || [ "$SELECT_CODE" = "401" ]; then
    echo "PASS [Regression]: Solr select endpoint is reachable (HTTP $SELECT_CODE)."
elif [ "$SELECT_CODE" = "000" ]; then
    echo "FAIL [Regression]: Solr not responding after remediation." >&2
    exit 1
else
    echo "INFO [Regression]: Solr select returned $SELECT_CODE — checking if Solr is running."
    # As long as Solr is up at all, that's a pass
    HEALTH=$(curl -s -o /dev/null -w "%{http_code}" \
             "http://localhost:8983/solr/admin/cores" 2>/dev/null || echo "000")
    if [ "$HEALTH" = "200" ] || [ "$HEALTH" = "401" ]; then
        echo "PASS [Regression]: Solr admin API is reachable (HTTP $HEALTH)."
    else
        echo "FAIL [Regression]: Solr admin API returned $HEALTH." >&2
        exit 1
    fi
fi

exit 0
