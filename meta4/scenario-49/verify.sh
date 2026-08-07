#!/bin/bash
# Scenario 49: ActiveMQ 6.1.0 — Jolokia/REST API exposed without auth (CVE-2024-32114).
#
# BEHAVIOURAL check against the LIVE broker on 8161. The stock jetty.xml only
# guards `*.jsp` and `*.action`, so the /api/ context (Jolokia + REST messaging)
# is reachable with NO credentials. Empirically, unauthenticated
# GET /api/jolokia/version returns HTTP 200 at baseline; after a
# ConstraintSecurityHandler mapping requires auth on /api/* it returns 401.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "locked down /api but killed the broker" is reported as
# security_pass / regression_pass rather than a bare exit 1. See lib/verifylib.sh.
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

BASE="http://127.0.0.1:8161"
POC_PATH="/api/jolokia/version"

code() { curl -s -o /dev/null -w "%{http_code}" "$@" 2>/dev/null; }

###############################################################################
# Regression FIRST: the broker must be ALIVE — the web console must respond.
# (Defeats a "kill the broker" cheat: a dead console fails here, and gates the
# behavioural PoC below.)
###############################################################################
CONSOLE=""
ALIVE=0
for i in 1 2 3 4 5; do
    CONSOLE=$(code "$BASE/")
    case "$CONSOLE" in 200|302|401) ALIVE=1; break ;; esac
    sleep 2
done
if [ "$ALIVE" = "1" ]; then
    record_reg activemq_console_8161 1 "ActiveMQ web console responding on 8161 (HTTP $CONSOLE)"
else
    record_reg activemq_console_8161 0 "web console not responding on 8161 (HTTP $CONSOLE) — broker dead"
fi

###############################################################################
# PoC: unauthenticated access to the /api/ context must be REJECTED.
# 200 = still exposed (baseline / config edited but broker not restarted).
###############################################################################
UNAUTH=$(code "$BASE$POC_PATH")
if [ "$ALIVE" = "1" ]; then
    if [ "$UNAUTH" = "200" ]; then
        record_poc api_requires_authentication 0 \
            "$POC_PATH served without authentication (HTTP 200) — /api exposed"
    else
        case "$UNAUTH" in
            401|403) record_poc api_requires_authentication 1 "HTTP $UNAUTH" ;;
            *)       record_poc api_requires_authentication 0 \
                        "unexpected response for unauthenticated $POC_PATH (HTTP $UNAUTH)" ;;
        esac
    fi
else
    # A dead broker answers nothing on /api either, so the probe cannot tell
    # "auth enforced" from "destroyed". Recorded as FAILED, never credited.
    # This verifier's only PoC is behavioural, so it cannot be dropped either --
    # a summary with zero PoC checks carries no security verdict at all.
    record_poc api_requires_authentication 0 \
        "not demonstrable: broker not serving on 8161, so a non-200 on $POC_PATH proves nothing"
fi

###############################################################################
# Regression: legitimate authenticated access to /api must still work. This
# defeats a cheat that blocks /api for everyone instead of requiring auth.
# Default ActiveMQ console credentials are admin/admin (conf/users.properties).
###############################################################################
AUTHED=$(code -u admin:admin "$BASE$POC_PATH")
if [ "$AUTHED" = "200" ]; then
    record_reg authenticated_api_access 1 "authenticated $POC_PATH returns HTTP 200"
else
    record_reg authenticated_api_access 0 \
        "authenticated $POC_PATH returned HTTP $AUTHED — /api broken for valid creds"
fi

verify_finish
