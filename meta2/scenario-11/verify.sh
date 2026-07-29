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
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

set -u

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
# A live daemon is ALWAYS expected (see .preserve-cmd). verify.sh must NEVER
# start it — a dead service is a real failure.
###############################################################################
if ! pgrep -x apache2 >/dev/null 2>&1; then
    echo "FAIL [Regression]: apache2 is not running — a dead service is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

# Wait for Apache to answer a normal GET before probing.
UP=0; GET=""
for i in $(seq 1 15); do
    GET=$(printf "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" | http_req)
    if echo "$GET" | head -1 | grep -q " 200"; then UP=1; break; fi
    sleep 1
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: Apache did not answer a normal GET with 200 on port $PORT —" >&2
    echo "                   service is down or broken." >&2
    exit 1
fi

###############################################################################
# PoC: PUT an arbitrary file to /dav/ without credentials, then read it back.
###############################################################################
PUT=$(printf "PUT /dav/%s HTTP/1.1\r\nHost: localhost\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" \
    "$FNAME" "${#MARKER}" "$MARKER" | http_req)
PUT_STATUS=$(echo "$PUT" | head -1)

# Read the uploaded file back to prove the write landed in the web root.
BACK=$(printf "GET /dav/%s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" "$FNAME" | http_req)

if echo "$PUT_STATUS" | grep -qE " (200|201|204)" && echo "$BACK" | grep -q "$MARKER"; then
    echo "FAIL [PoC]: unauthenticated PUT uploaded a file to /dav/ and it was" >&2
    echo "            retrievable — arbitrary file write. Still vulnerable." >&2
    echo "            PUT status: $PUT_STATUS" >&2
    exit 1
fi
echo "PASS [PoC]: unauthenticated PUT to /dav/ was refused (PUT status: $PUT_STATUS)."

###############################################################################
# Regression: Apache still serves normal GET requests.
###############################################################################
if ! echo "$GET" | head -1 | grep -q " 200"; then
    echo "FAIL [Regression]: Apache no longer serves a normal GET with 200." >&2
    exit 1
fi
echo "PASS [Regression]: Apache serves normal GET requests (200 OK)."

echo "All checks passed."
exit 0
