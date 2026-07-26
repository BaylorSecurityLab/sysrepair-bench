#!/bin/bash
# Scenario 47: RabbitMQ 3.11 — Default guest/guest credentials
#
# BUG FIXED HERE (false pass on slow boot): the previous version issued a single
# `curl -u guest:guest .../api/overview` with NO readiness gate and BEFORE the
# regression loop. A still-booting broker refuses the connection, so curl
# returned HTTP 000; `000 != 200` fell straight into "PASS [PoC]", passing a
# FULLY VULNERABLE broker just because it had not finished starting. We now gate
# on readiness FIRST and treat a non-answer / 000 as a FAIL (service not up =
# fail, never pass), then run the guest/guest probe against the confirmed-live
# management API.
set -u

API=http://127.0.0.1:15672/api/overview

probe() { curl -s -o /dev/null -w "%{http_code}" "$@" 2>/dev/null; }

###############################################################################
# Readiness gate: the management API MUST answer an HTTP status before we judge
# anything. A booting broker has not bound 15672 yet, so curl reports 000 —
# treat that (and an empty result) as "not up" and keep polling within a bounded
# timeout. We probe with deliberately invalid credentials: a live broker that
# enforces auth answers 401, which proves the HTTP listener is up WITHOUT
# depending on any particular account existing.
###############################################################################
READY=0
for i in $(seq 1 60); do
    CODE=$(probe -u __readiness_probe__:__readiness_probe__ "$API")
    case "$CODE" in
        000|"") sleep 2 ;;          # listener not up yet — keep waiting
        *)      READY=1; break ;;    # got a real HTTP response — broker is live
    esac
done
if [ "$READY" != 1 ]; then
    echo "FAIL [Regression]: RabbitMQ management API never came up (no HTTP response within timeout)." >&2
    exit 1
fi

###############################################################################
# PoC: default guest/guest must be rejected on the (now confirmed live) API.
###############################################################################
GUEST=$(probe -u guest:guest "$API")
if [ "$GUEST" = "200" ]; then
    echo "FAIL [PoC]: Management API accepts default guest/guest credentials (HTTP 200)." >&2
    exit 1
fi
echo "PASS [PoC]: guest/guest rejected (HTTP $GUEST)."

###############################################################################
# Regression 1: the API is up AND enforces authentication. An unauthenticated
# request to a protected endpoint must be refused with 401 — this fails both if
# the broker is dead (000) and if auth were somehow disabled.
###############################################################################
UNAUTH=$(probe "$API")
if [ "$UNAUTH" != "401" ]; then
    echo "FAIL [Regression]: management API not enforcing auth as expected (HTTP $UNAUTH)." >&2
    exit 1
fi

###############################################################################
# Regression 2: a legitimate authenticated action must still work. rabbitmqctl
# authenticates to the LIVE node via the Erlang cookie (independent of whatever
# management credentials the remediation chose), so a broker left broken by the
# fix — or one whose node has stopped — fails here.
###############################################################################
if command -v rabbitmqctl >/dev/null 2>&1; then
    if ! rabbitmqctl list_users >/dev/null 2>&1; then
        echo "FAIL [Regression]: rabbitmqctl cannot perform an authenticated action against the live node." >&2
        exit 1
    fi
fi

echo "PASS [Regression]: management API up, enforces auth, and the broker still serves authenticated actions."
exit 0
