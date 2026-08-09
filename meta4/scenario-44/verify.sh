#!/bin/bash
# Scenario 44: Elasticsearch 7.10.1 — X-Pack Security Disabled (misconfig)
#
# PoC (DYNAMIC, against the LIVE node on :9200): an unauthenticated request to
# the root endpoint must be REJECTED (401).  A 200 means security is off on the
# running node — including the "flipped the config but never restarted" case.
# Regression: an AUTHENTICATED request (elastic:changeme) must succeed.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "enabled X-Pack but killed the node" is reported as
# security_pass / regression_pass rather than a bare exit 1. See lib/verifylib.sh.
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

ES_URL="http://localhost:9200"
ELASTIC_PASSWORD="${ELASTIC_PASSWORD:-changeme}"

###############################################################################
# Wait until ES answers at all, so a slow boot is not mistaken for "fixed" and
# the PoC tests the real running node.
###############################################################################
CODE="000"
for i in $(seq 1 60); do
    # No `|| echo 000` here: curl already PRINTS 000 via -w on a failed connect,
    # so an added fallback would make CODE the two-line string "000\n000" and the
    # `!= 000` readiness test would break out on a dead node.
    CODE=$(curl -s -o /dev/null -w "%{http_code}" "${ES_URL}/" 2>/dev/null)
    [ "$CODE" != "000" ] && break
    sleep 2
done
if [ "$CODE" != "000" ]; then
    record_reg elasticsearch_answers_http 1 "HTTP $CODE"
else
    record_reg elasticsearch_answers_http 0 "Elasticsearch not reachable on 9200 (service down)"
fi

if [ "$CODE" != "000" ]; then
    ###########################################################################
    # PoC (DYNAMIC): unauthenticated request must be denied
    ###########################################################################
    if [ "$CODE" = "200" ]; then
        record_poc unauthenticated_access_denied 0 \
            "unauthenticated GET / returned 200 — X-Pack security is disabled on the live node"
    elif [ "$CODE" != "401" ]; then
        record_poc unauthenticated_access_denied 0 \
            "unauthenticated GET / returned unexpected HTTP ${CODE} (expected 401 with security enabled)"
    else
        record_poc unauthenticated_access_denied 1
    fi
else
    # The node never produced an HTTP status, so "no 200" proves nothing about
    # X-Pack. Recorded as FAILED, never credited: a dead node also declines the
    # unauthenticated request, and that must not read as a secured one. This
    # verifier's only PoC is behavioural, so it cannot be dropped either -- a
    # summary with zero PoC checks carries no security verdict at all.
    record_poc unauthenticated_access_denied 0 \
        "not demonstrable: Elasticsearch unreachable on 9200, so the absence of a 200 proves nothing"
fi

###############################################################################
# Regression: authenticated cluster health must be reachable
###############################################################################
HEALTH_OK=0
HEALTH=""
for i in $(seq 1 20); do
    HEALTH=$(curl -s -u "elastic:${ELASTIC_PASSWORD}" \
        "${ES_URL}/_cluster/health" 2>/dev/null | grep -oE '"status"[[:space:]]*:[[:space:]]*"[^"]+"' || true)
    if echo "$HEALTH" | grep -qE '"(green|yellow)"'; then
        HEALTH_OK=1
        break
    fi
    sleep 3
done
if [ "$HEALTH_OK" = "1" ]; then
    record_reg authenticated_cluster_health 1 "${HEALTH}"
else
    record_reg authenticated_cluster_health 0 \
        "cluster health endpoint not reachable with elastic:${ELASTIC_PASSWORD}"
fi

verify_finish
