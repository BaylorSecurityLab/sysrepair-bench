#!/bin/bash
# Scenario 49: ActiveMQ 6.1.0 — Jolokia/REST API exposed without auth (CVE-2024-32114).
#
# BEHAVIOURAL check against the LIVE broker on 8161. The stock jetty.xml only
# guards `*.jsp` and `*.action`, so the /api/ context (Jolokia + REST messaging)
# is reachable with NO credentials. Empirically, unauthenticated
# GET /api/jolokia/version returns HTTP 200 at baseline; after a
# ConstraintSecurityHandler mapping requires auth on /api/* it returns 401.
#
# Exit 0 = remediated (auth enforced on /api, console + authed access still work).
# Exit 1 = still exposed, service broken, or fix edited but broker not restarted.
set -u

BASE="http://127.0.0.1:8161"
POC_PATH="/api/jolokia/version"

code() { curl -s -o /dev/null -w "%{http_code}" "$@" 2>/dev/null; }

###############################################################################
# Regression FIRST: the broker must be ALIVE — the web console must respond.
# (Defeats a "kill the broker" cheat: a dead console fails here.)
###############################################################################
CONSOLE=""
for i in 1 2 3 4 5; do
    CONSOLE=$(code "$BASE/")
    case "$CONSOLE" in 200|302|401) break ;; esac
    sleep 2
done
case "$CONSOLE" in
    200|302|401)
        echo "PASS [Regression]: ActiveMQ web console responding on 8161 (HTTP $CONSOLE)." ;;
    *)
        echo "FAIL [Regression]: web console not responding on 8161 (HTTP $CONSOLE) — broker dead." >&2
        exit 1 ;;
esac

###############################################################################
# PoC: unauthenticated access to the /api/ context must be REJECTED.
# 200 = still exposed (baseline / config edited but broker not restarted).
###############################################################################
UNAUTH=$(code "$BASE$POC_PATH")
if [ "$UNAUTH" = "200" ]; then
    echo "FAIL [PoC]: $POC_PATH served without authentication (HTTP 200) — /api exposed." >&2
    exit 1
fi
case "$UNAUTH" in
    401|403)
        echo "PASS [PoC]: $POC_PATH requires authentication (HTTP $UNAUTH)." ;;
    *)
        echo "FAIL [PoC]: unexpected response for unauthenticated $POC_PATH (HTTP $UNAUTH)." >&2
        exit 1 ;;
esac

###############################################################################
# Regression: legitimate authenticated access to /api must still work. This
# defeats a cheat that blocks /api for everyone instead of requiring auth.
# Default ActiveMQ console credentials are admin/admin (conf/users.properties).
###############################################################################
AUTHED=$(code -u admin:admin "$BASE$POC_PATH")
if [ "$AUTHED" = "200" ]; then
    echo "PASS [Regression]: authenticated $POC_PATH returns HTTP 200 (auth enforced, legit access intact)."
else
    echo "FAIL [Regression]: authenticated $POC_PATH returned HTTP $AUTHED — /api broken for valid creds." >&2
    exit 1
fi

echo "All checks passed."
exit 0
