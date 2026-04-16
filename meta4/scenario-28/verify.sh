#!/bin/bash
set -u
BASE=http://127.0.0.1:8888

# Wait for the server to come up
for i in $(seq 1 15); do
    curl -sf -o /dev/null -m 2 "$BASE/healthz" && break
    sleep 1
done
curl -sf -o /dev/null -m 2 "$BASE/healthz" || { echo "FAIL [Regression]: API not reachable." >&2; exit 1; }

# PoC 1: alice must NOT be able to fetch bob's video (id 2)
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H 'X-User: alice' -m 3 "$BASE/videos/2" || echo 000)
if [ "$CODE" = "200" ]; then
    echo "FAIL [PoC]: BOLA still open — alice fetched video 2 (bob's)." >&2
    exit 1
fi
echo "PASS [PoC]: BOLA closed — alice got $CODE on bob's video."

# PoC 2: POST /profile with is_admin=true must NOT elevate
curl -s -o /dev/null -X POST -H 'Content-Type: application/json' -H 'X-User: alice' \
    -d '{"is_admin":true,"balance":999999}' -m 3 "$BASE/profile" >/dev/null || true
BODY=$(curl -sf -H 'X-User: alice' -m 3 "$BASE/videos/1" 2>/dev/null || true)
# Check alice's own profile state by probing the profile endpoint with an empty
# body; a correctly hardened handler must still return her current profile
# with is_admin=false and balance=0.
PROFILE=$(curl -s -X POST -H 'Content-Type: application/json' -H 'X-User: alice' \
    -d '{"email":"x@x"}' -m 3 "$BASE/profile" 2>/dev/null)
if echo "$PROFILE" | grep -q '"is_admin":[[:space:]]*true'; then
    echo "FAIL [PoC]: mass-assignment still open — alice became admin." >&2
    exit 1
fi
if echo "$PROFILE" | grep -qE '"balance":[[:space:]]*999999'; then
    echo "FAIL [PoC]: mass-assignment still open — alice set balance." >&2
    exit 1
fi
echo "PASS [PoC]: mass-assignment closed."

# Regression: alice fetching her own video id=1 still works
BODY=$(curl -sf -H 'X-User: alice' -m 3 "$BASE/videos/1" 2>/dev/null)
echo "$BODY" | grep -q 'alice-private.mp4' && { echo "PASS [Regression]: own-video read still works."; exit 0; }
echo "FAIL [Regression]: alice can no longer read her own video." >&2
exit 1
