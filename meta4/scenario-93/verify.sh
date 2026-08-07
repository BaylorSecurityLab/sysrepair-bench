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
# The regression component it used to (wrongly) provide is now supplied by the
# baseline-valid liveness probe further down.
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

###############################################################################
# REGRESSION: the notebook server must still be serving HTTP on 8888.
#
# This is the liveness component the reclassification above removed. `/` is the
# right probe because it answers in BOTH states -- 302 on the untouched box
# (redirect to /tree, auth disabled) and 302 once a token is set (redirect to
# /login) -- so it satisfies the invariant that a regression check passes at
# baseline. It goes FALSE the instant the notebook process dies, because a dead
# listener yields curl exit != 0 and HTTP 000.
#
# Behavioural on purpose: `ps`/comm matching for "jupyter" also matches a zombie
# left behind by a non-reaping parent, so a destroyed server would read as alive.
# A request that must be answered cannot be satisfied by a corpse.
###############################################################################

JUP_LIVE=0
JUP_LIVE_CODE="000"
for i in 1 2 3 4 5; do
    JUP_LIVE_CODE=$(curl -s -m 5 -o /dev/null -w "%{http_code}" http://localhost:8888/ 2>/dev/null || echo "000")
    case "$JUP_LIVE_CODE" in
        2??|3??|401|403) JUP_LIVE=1; break;;
    esac
    sleep 2
done

if [ "$JUP_LIVE" = "1" ]; then
    record_reg notebook_http_alive 1 "notebook server answered GET / on port 8888 (HTTP $JUP_LIVE_CODE)"
else
    record_reg notebook_http_alive 0 "notebook server did not answer GET / on port 8888 (last HTTP $JUP_LIVE_CODE) - the service was destroyed"
fi

verify_finish
