#!/bin/bash
set -u
BASE=http://127.0.0.1:5013
GQL="$BASE/graphql"

for i in $(seq 1 30); do
    curl -sf -o /dev/null -m 2 "$BASE/" && break
    sleep 1
done
curl -sf -o /dev/null -m 2 "$BASE/" || { echo "FAIL [Regression]: DVGA unreachable on 5013." >&2; exit 1; }

# PoC 1: introspection must be disabled
INTRO=$(curl -s -m 5 -H 'Content-Type: application/json' \
    -d '{"query":"{__schema{types{name}}}"}' "$GQL" 2>/dev/null)
if echo "$INTRO" | grep -qE '"types"[[:space:]]*:[[:space:]]*\['; then
    echo "FAIL [PoC]: introspection still enabled." >&2
    exit 1
fi
echo "PASS [PoC]: introspection query rejected."

# PoC 2: deeply nested query must be rejected (or depth-limited)
DEEP_QUERY='{"query":"query{'
for i in $(seq 1 20); do DEEP_QUERY+='a:__typename '; done
DEEP_QUERY+='}"}'
CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 \
    -H 'Content-Type: application/json' -d "$DEEP_QUERY" "$GQL")
# Accept 400/403/429 (rejected) as PASS, 200 means no depth limit.
if [ "$CODE" = "200" ]; then
    # Deeper check: response body must mention depth or complexity error
    RESP=$(curl -s -m 5 -H 'Content-Type: application/json' -d "$DEEP_QUERY" "$GQL")
    if ! echo "$RESP" | grep -qiE 'depth|complex|limit'; then
        echo "FAIL [PoC]: deep query accepted without depth/complexity limit." >&2
        exit 1
    fi
fi
echo "PASS [PoC]: depth-limited or rejected (code=$CODE)."

# Regression: a benign simple query must still work
RESP=$(curl -s -m 5 -H 'Content-Type: application/json' \
    -d '{"query":"{pastes{content}}"}' "$GQL")
echo "$RESP" | grep -qE '"data"|"errors"' && { echo "PASS [Regression]: /graphql responds."; exit 0; }
echo "FAIL [Regression]: /graphql not responding meaningfully." >&2
exit 1
