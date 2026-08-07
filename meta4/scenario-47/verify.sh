#!/bin/bash
# Scenario 47: RabbitMQ 3.11 — Default guest/guest credentials
#
# BUG FIXED EARLIER (false pass on slow boot): an older version issued a single
# `curl -u guest:guest .../api/overview` with NO readiness gate. A still-booting
# broker refuses the connection, so curl returned HTTP 000; `000 != 200` fell
# straight into "PASS [PoC]", passing a FULLY VULNERABLE broker just because it
# had not finished starting. We gate on readiness FIRST and treat a non-answer /
# 000 as a regression failure with the PoC left UNRECORDED (service not up is
# never a pass), then run the guest/guest probe against the confirmed-live API.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "removed guest/guest but killed the broker" is reported as
# security_pass / regression_pass rather than a bare exit 1. See lib/verifylib.sh.
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

API=http://127.0.0.1:15672/api/overview

# No `|| echo 000`: curl already PRINTS 000 via -w on a failed connect, so an
# added fallback would make CODE the two-line string "000\n000" and the readiness
# gate would accept a dead broker as live.
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
if [ "$READY" = "1" ]; then
    record_reg management_api_up 1
else
    record_reg management_api_up 0 "RabbitMQ management API never came up (no HTTP response within timeout)"
fi

###############################################################################
# PoC: default guest/guest must be rejected on the (now confirmed live) API.
###############################################################################
if [ "$READY" = "1" ]; then
    GUEST=$(probe -u guest:guest "$API")
    if [ "$GUEST" = "200" ]; then
        record_poc guest_credentials_rejected 0 \
            "management API accepts default guest/guest credentials (HTTP 200)"
    else
        record_poc guest_credentials_rejected 1 "HTTP $GUEST"
    fi
else
    # With the API dead every credential is "rejected". Recorded as FAILED,
    # never credited: killing the broker must not read as having removed the
    # default account. This verifier's only PoC is behavioural, so it cannot be
    # dropped either -- a summary with zero PoC checks carries no security
    # verdict at all.
    record_poc guest_credentials_rejected 0 \
        "not demonstrable: management API unreachable, so a rejected guest/guest proves nothing"
fi

###############################################################################
# Regression 1: the API is up AND enforces authentication. An unauthenticated
# request to a protected endpoint must be refused with 401 — this fails both if
# the broker is dead (000) and if auth were somehow disabled.
###############################################################################
UNAUTH=$(probe "$API")
if [ "$UNAUTH" = "401" ]; then
    record_reg management_api_enforces_auth 1
else
    record_reg management_api_enforces_auth 0 "management API not enforcing auth as expected (HTTP $UNAUTH)"
fi

###############################################################################
# Regression 2: a legitimate authenticated action must still work. rabbitmqctl
# authenticates to the LIVE node via the Erlang cookie (independent of whatever
# management credentials the remediation chose), so a broker left broken by the
# fix — or one whose node has stopped — fails here.
###############################################################################
if command -v rabbitmqctl >/dev/null 2>&1; then
    if rabbitmqctl list_users >/dev/null 2>&1; then
        record_reg rabbitmqctl_authenticated_action 1
    else
        record_reg rabbitmqctl_authenticated_action 0 \
            "rabbitmqctl cannot perform an authenticated action against the live node"
    fi
else
    echo "  [SKIP] (regression) rabbitmqctl_authenticated_action: rabbitmqctl not present"
fi

verify_finish
