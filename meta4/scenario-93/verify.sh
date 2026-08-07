#!/bin/bash
# Scenario 93: Jupyter Notebook — No Token Authentication (misconfig)
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

###############################################################################
# PoC: unauthenticated /api/contents must return 401 or 403
###############################################################################

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/api/contents 2>/dev/null || echo "000")

if echo "$HTTP_CODE" | grep -qE '^(401|403)$'; then
    record_poc unauth_api_denied 1 "unauthenticated /api/contents returns HTTP $HTTP_CODE"
else
    record_poc unauth_api_denied 0 "/api/contents returned HTTP $HTTP_CODE (expected 401 or 403)"
fi

###############################################################################
# The /login route must answer on port 8888.
#
# RECLASSIFIED regression -> poc. On the untouched box token auth is DISABLED
# (that IS the vulnerability), and Jupyter then never registers a /login route --
# measured: / => 302, /tree => 200, /api/contents => 200, but /login => 404. So
# this check can only pass AFTER auth is turned on, which by the invariant makes
# it a PoC check, not a regression check. It was previously unreachable at
# baseline (the verifier exited at the failing PoC above), so the mislabel was
# invisible under the single-exit-code protocol. Condition, strictness and the
# exit-0 state set are unchanged.
#
# NOTE for the scenario owner: this leaves scenario 93 with NO regression check,
# so it cannot witness collateral damage. Fixing that needs a baseline-valid
# liveness probe (e.g. / or /tree, which answer in BOTH states) -- that is a new
# check, which is out of scope for this migration.
###############################################################################

JUP_OK=0
JUP_WHY=""
for i in 1 2 3 4 5; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/login 2>/dev/null || echo "000")
    if echo "$STATUS" | grep -qE '^(200|302|301)$'; then
        JUP_OK=1
        JUP_WHY="Jupyter login route reachable on port 8888 (HTTP $STATUS)"
        break
    fi
    sleep 3
done

if [ "$JUP_OK" = "1" ]; then
    record_poc jupyter_login_route 1 "$JUP_WHY"
else
    record_poc jupyter_login_route 0 "Jupyter /login not reachable on port 8888 after remediation"
fi

verify_finish
