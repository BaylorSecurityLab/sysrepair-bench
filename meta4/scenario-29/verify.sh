#!/bin/bash
# Dynamic verifier for DVGA GraphQL introspection + unbounded-query hardening.
#
# Probes the LIVE server on :5013. GraphQL returns HTTP 200 even for rejected
# queries (the error rides in the JSON body), so every check inspects the BODY,
# not the status code. This script must NOT start DVGA - a dead daemon is a FAIL
# - so the "patched source but never restarted" case stays detectable.
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "disabled introspection but killed DVGA" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

BASE=http://127.0.0.1:5013
GQL="$BASE/graphql"

for i in $(seq 1 30); do
    curl -sf -o /dev/null -m 2 "$BASE/" && break
    sleep 1
done
if curl -sf -o /dev/null -m 2 "$BASE/"; then
    record_reg dvga_reachable 1
else
    record_reg dvga_reachable 0 "DVGA unreachable on 5013 (daemon not running / not restarted)"
fi

###############################################################################
# PoC 1: introspection must be disabled - a __schema query must NOT leak types.
###############################################################################
INTRO=$(curl -s -m 6 -H 'Content-Type: application/json' \
    -d '{"query":"{__schema{types{name}}}"}' "$GQL" 2>/dev/null || true)
if echo "$INTRO" | grep -q '"types"'; then
    record_poc introspection_disabled 0 "introspection still enabled - __schema leaked the type list"
else
    record_poc introspection_disabled 1
fi

###############################################################################
# PoC 2: a genuinely deep (space-delimited, so DVGA's depth parser sees it),
# recursive pastes->owner->pastes query must be rejected by a depth limit.
#
# A response that is neither a depth rejection nor a data payload means the
# endpoint did not answer at all - that is an unreachable service, not an open
# vulnerability, so it is recorded as regression damage with the depth-limit PoC
# left unmeasured. Otherwise killing DVGA would read as having added a limit.
###############################################################################
DEEP='{ pastes { owner { pastes { owner { pastes { owner { pastes { owner { pastes { owner { name } } } } } } } } } } }'
RESP=$(curl -s -m 8 -H 'Content-Type: application/json' \
    -d "{\"query\":\"$DEEP\"}" "$GQL" 2>/dev/null || true)
if echo "$RESP" | grep -qiE 'depth|recursion|complex|exceeded|too high'; then
    record_reg graphql_depth_probe_answered 1
    record_poc depth_limit_enforced 1 "deep query rejected by depth/complexity limit"
elif echo "$RESP" | grep -q '"data"'; then
    record_reg graphql_depth_probe_answered 1
    record_poc depth_limit_enforced 0 "deep recursive query accepted - no depth/complexity limit"
else
    record_reg graphql_depth_probe_answered 0 "/graphql did not answer the depth probe meaningfully"
fi

###############################################################################
# Regression: a benign simple query must still return data.
###############################################################################
REG=$(curl -s -m 6 -H 'Content-Type: application/json' \
    -d '{"query":"{pastes{content}}"}' "$GQL" 2>/dev/null || true)
if echo "$REG" | grep -q '"data"'; then
    record_reg benign_query_works 1
else
    record_reg benign_query_works 0 "benign /graphql query no longer returns data"
fi

verify_finish
