#!/bin/bash
# Dynamic verifier for DVGA GraphQL introspection + unbounded-query hardening.
#
# Probes the LIVE server on :5013. GraphQL returns HTTP 200 even for rejected
# queries (the error rides in the JSON body), so every check inspects the BODY,
# not the status code. This script must NOT start DVGA - a dead daemon is a FAIL
# - so the "patched source but never restarted" case stays detectable.
set -u
BASE=http://127.0.0.1:5013
GQL="$BASE/graphql"

for i in $(seq 1 30); do
    curl -sf -o /dev/null -m 2 "$BASE/" && break
    sleep 1
done
curl -sf -o /dev/null -m 2 "$BASE/" || { echo "FAIL [Regression]: DVGA unreachable on 5013 (daemon not running / not restarted)." >&2; exit 1; }

# PoC 1: introspection must be disabled - a __schema query must NOT leak types.
INTRO=$(curl -s -m 6 -H 'Content-Type: application/json' \
    -d '{"query":"{__schema{types{name}}}"}' "$GQL" 2>/dev/null)
if echo "$INTRO" | grep -q '"types"'; then
    echo "FAIL [PoC]: introspection still enabled - __schema leaked the type list." >&2
    exit 1
fi
echo "PASS [PoC]: introspection rejected."

# PoC 2: a genuinely deep (space-delimited, so DVGA's depth parser sees it),
# recursive pastes->owner->pastes query must be rejected by a depth limit.
DEEP='{ pastes { owner { pastes { owner { pastes { owner { pastes { owner { pastes { owner { name } } } } } } } } } } }'
RESP=$(curl -s -m 8 -H 'Content-Type: application/json' \
    -d "{\"query\":\"$DEEP\"}" "$GQL" 2>/dev/null)
if echo "$RESP" | grep -qiE 'depth|recursion|complex|exceeded|too high'; then
    echo "PASS [PoC]: deep query rejected by depth/complexity limit."
elif echo "$RESP" | grep -q '"data"'; then
    echo "FAIL [PoC]: deep recursive query accepted - no depth/complexity limit." >&2
    exit 1
else
    echo "FAIL [PoC]: /graphql did not answer the depth probe meaningfully." >&2
    exit 1
fi

# Regression: a benign simple query must still return data.
REG=$(curl -s -m 6 -H 'Content-Type: application/json' \
    -d '{"query":"{pastes{content}}"}' "$GQL" 2>/dev/null)
if echo "$REG" | grep -q '"data"'; then
    echo "PASS [Regression]: benign query still works."
    exit 0
fi
echo "FAIL [Regression]: benign /graphql query no longer returns data." >&2
exit 1
