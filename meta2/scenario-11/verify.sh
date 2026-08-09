#!/bin/bash
# Scenario 11: Apache Dangerous HTTP Methods (PUT/DELETE via WebDAV)
#
# BEHAVIOURAL verifier. It does NOT grep the Apache config — it performs a REAL
# unauthenticated WebDAV attack: PUT a file with a unique marker to /dav/, then
# GET it back. If the upload succeeds (2xx) AND the marker is retrievable, an
# unauthenticated attacker can write arbitrary files to the web root and the box
# is vulnerable. Once WebDAV is disabled / requires auth, the PUT is refused
# (401/403/405). A defender who edits the config but never restarts Apache is
# still exposed, and the live upload proves it.
#
# PoC checks:        an unauthenticated PUT to /dav/ no longer lands a readable file
# Regression checks: apache2 runs and still serves a normal GET with 200
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# UNREACHABILITY: a dead server accepts no PUT and serves no file back, so a
# killed Apache would read as "arbitrary write closed". The PoC is left
# UNRECORDED unless the normal GET proved the server is answering.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

HOST=127.0.0.1
PORT=80
FNAME="poc_$$_$RANDOM.txt"
MARKER="PWNED-WEBDAV-9f3a2b"

http_req() { nc -w 5 "$HOST" "$PORT" 2>/dev/null; }

cleanup() {
    printf "DELETE /dav/%s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" "$FNAME" | http_req >/dev/null 2>&1 || true
}
trap cleanup EXIT

###############################################################################
# Regression: a live daemon is ALWAYS expected (see .preserve-cmd). verify.sh
# must NEVER start it — a dead service is a real failure.
###############################################################################
if pgrep -x apache2 >/dev/null 2>&1; then
    record_reg apache2_running 1
else
    record_reg apache2_running 0 "apache2 is not running (verify.sh must not start it)"
fi

###############################################################################
# Regression: Apache must answer a normal GET with 200 before the PUT reading
# can be trusted. The fail-fast version tested this same captured response twice
# — as a readiness gate and as the closing regression assertion — so it is
# recorded once.
###############################################################################
UP=0
GET=""
for i in $(seq 1 15); do
    GET=$(printf "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" | http_req) || true
    if echo "$GET" | head -1 | grep -q " 200"; then UP=1; break; fi
    sleep 1
done

if [ "$UP" = "1" ]; then
    record_reg apache_serves_get 1
else
    record_reg apache_serves_get 0 \
        "Apache did not answer a normal GET with 200 on port $PORT — service is down or broken"
fi

###############################################################################
# PoC: PUT an arbitrary file to /dav/ without credentials, then read it back.
###############################################################################
if [ "$UP" = "1" ]; then
    PUT=$(printf "PUT /dav/%s HTTP/1.1\r\nHost: localhost\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" \
        "$FNAME" "${#MARKER}" "$MARKER" | http_req) || true
    PUT_STATUS=$(echo "$PUT" | head -1) || true

    # Read the uploaded file back to prove the write landed in the web root.
    BACK=$(printf "GET /dav/%s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" "$FNAME" | http_req) || true

    if echo "$PUT_STATUS" | grep -qE " (200|201|204)" && echo "$BACK" | grep -q "$MARKER"; then
        record_poc unauth_put_refused 0 \
            "unauthenticated PUT uploaded a file to /dav/ and it was retrievable — arbitrary file write; PUT status: $PUT_STATUS"
    else
        record_poc unauth_put_refused 1
    fi
else
    echo "  [SKIP] (poc) unauth_put_refused: Apache is unreachable, so no PUT can land"
    echo "         and nothing is retrievable regardless of the WebDAV config. Left"
    echo "         unrecorded so that killing the service cannot read as closing the"
    echo "         vulnerability."
fi

verify_finish
