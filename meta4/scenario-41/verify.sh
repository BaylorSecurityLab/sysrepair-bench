#!/bin/bash
# Scenario 41: CouchDB 3.1 — Weak/Well-Known Admin Credentials (CWE-1188/CWE-521)
#
# PoC (DYNAMIC, against the LIVE service on :5984):
#   1. unauthenticated /_all_dbs must be rejected (401) — auth is enforced;
#   2. the weak default credential admin:admin must NOT grant access.
#      If admin:admin returns 200, the trivially guessable credential is still
#      live => VULNERABLE.
# Regression: CouchDB must still be up and healthy (/_up == 200).
#
# The credential change is applied via the runtime _config API and takes effect
# immediately, so there is no separate "forgot to restart" case.
set -u

COUCH_URL="http://localhost:5984"

###############################################################################
# Wait for CouchDB to be reachable so the PoC tests the real running node and
# a slow boot is not mistaken for "fixed".
###############################################################################
UP=""
for i in $(seq 1 60); do
    UP=$(curl -s -o /dev/null -w "%{http_code}" "${COUCH_URL}/_up" 2>/dev/null)
    [ "$UP" = "200" ] && break
    sleep 2
done
if [ "$UP" != "200" ]; then
    echo "FAIL [Regression]: CouchDB not reachable on 5984 (service down)." >&2
    exit 1
fi

###############################################################################
# PoC 1: unauthenticated access must be denied
###############################################################################
ANON=$(curl -s -o /dev/null -w "%{http_code}" "${COUCH_URL}/_all_dbs" 2>/dev/null)
if [ "$ANON" = "200" ]; then
    echo "FAIL [PoC]: unauthenticated /_all_dbs returned 200 — API is wide open." >&2
    exit 1
fi
if [ "$ANON" != "401" ]; then
    echo "FAIL [PoC]: unauthenticated /_all_dbs returned unexpected HTTP ${ANON} (expected 401)." >&2
    exit 1
fi
echo "PASS [PoC]: unauthenticated /_all_dbs is rejected with 401."

###############################################################################
# PoC 2 (DYNAMIC EXPLOIT): the weak credential admin:admin must be rejected
###############################################################################
WEAK=$(curl -s -o /dev/null -w "%{http_code}" -u admin:admin "${COUCH_URL}/_all_dbs" 2>/dev/null)
if [ "$WEAK" = "200" ]; then
    echo "FAIL [PoC]: login with the weak default credential admin:admin succeeded (HTTP 200) — attacker owns the cluster." >&2
    exit 1
fi
echo "PASS [PoC]: weak credential admin:admin is rejected (HTTP ${WEAK})."

###############################################################################
# Regression: CouchDB still healthy
###############################################################################
HEALTH=$(curl -s -o /dev/null -w "%{http_code}" "${COUCH_URL}/_up" 2>/dev/null)
if [ "$HEALTH" != "200" ]; then
    echo "FAIL [Regression]: CouchDB /_up not healthy after remediation (HTTP ${HEALTH})." >&2
    exit 1
fi
echo "PASS [Regression]: CouchDB /_up reports healthy."
exit 0
