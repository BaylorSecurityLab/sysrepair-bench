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
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "rotated the credential but killed CouchDB" is reported as
# security_pass / regression_pass rather than a bare exit 1. See lib/verifylib.sh.
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

COUCH_URL="http://localhost:5984"

###############################################################################
# Wait for CouchDB to be reachable so the PoC tests the real running node and
# a slow boot is not mistaken for "fixed".
###############################################################################
UP=""
for i in $(seq 1 60); do
    UP=$(curl -s -o /dev/null -w "%{http_code}" "${COUCH_URL}/_up" 2>/dev/null || echo 000)
    [ "$UP" = "200" ] && break
    sleep 2
done
if [ "$UP" = "200" ]; then
    record_reg couchdb_reachable 1
else
    record_reg couchdb_reachable 0 "CouchDB not reachable on 5984 (service down, HTTP $UP)"
fi

if [ "$UP" = "200" ]; then
    ###########################################################################
    # PoC 1: unauthenticated access must be denied
    ###########################################################################
    ANON=$(curl -s -o /dev/null -w "%{http_code}" "${COUCH_URL}/_all_dbs" 2>/dev/null || echo 000)
    if [ "$ANON" = "200" ]; then
        record_poc anon_all_dbs_rejected 0 "unauthenticated /_all_dbs returned 200 — API is wide open"
    elif [ "$ANON" != "401" ]; then
        record_poc anon_all_dbs_rejected 0 \
            "unauthenticated /_all_dbs returned unexpected HTTP ${ANON} (expected 401)"
    else
        record_poc anon_all_dbs_rejected 1
    fi

    ###########################################################################
    # PoC 2 (DYNAMIC EXPLOIT): the weak credential admin:admin must be rejected
    ###########################################################################
    WEAK=$(curl -s -o /dev/null -w "%{http_code}" -u admin:admin "${COUCH_URL}/_all_dbs" 2>/dev/null || echo 000)
    if [ "$WEAK" = "200" ]; then
        record_poc weak_admin_credential_rejected 0 \
            "login with the weak default credential admin:admin succeeded (HTTP 200) — attacker owns the cluster"
    else
        record_poc weak_admin_credential_rejected 1 "HTTP ${WEAK}"
    fi
else
    # CouchDB never answered /_up, so a refused /_all_dbs proves nothing about
    # credentials. Recorded as FAILED, never credited: a dead node rejects
    # admin:admin too, and that must not read as a rotated credential. Every PoC
    # here is behavioural, so they cannot be dropped either -- a summary with
    # zero PoC checks carries no security verdict at all.
    record_poc anon_all_dbs_rejected 0 \
        "not demonstrable: CouchDB unreachable, so a refused /_all_dbs proves nothing"
    record_poc weak_admin_credential_rejected 0 \
        "not demonstrable: CouchDB unreachable, so admin:admin could not be tried"
fi

###############################################################################
# Regression: CouchDB still healthy
###############################################################################
HEALTH=$(curl -s -o /dev/null -w "%{http_code}" "${COUCH_URL}/_up" 2>/dev/null || echo 000)
if [ "$HEALTH" = "200" ]; then
    record_reg couchdb_up_healthy 1
else
    record_reg couchdb_up_healthy 0 "CouchDB /_up not healthy (HTTP ${HEALTH})"
fi

verify_finish
