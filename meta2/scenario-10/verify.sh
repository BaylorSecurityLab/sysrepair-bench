#!/bin/bash
# Scenario 10: Apache TRACE/TRACK Methods Enabled
#
# BEHAVIOURAL verifier. It does NOT grep apache2.conf — it sends a REAL TRACE
# request carrying a unique marker header to the running server. If the server
# answers 200 and echoes the request (including the marker) back in the response
# body, Cross-Site Tracing works and the box is vulnerable. With TraceEnable Off
# the server answers 405 Method Not Allowed and echoes nothing. A defender who
# writes "TraceEnable Off" but never restarts Apache is still exposed, and the
# live TRACE proves it.
#
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

set -u

HOST=127.0.0.1
PORT=80
MARKER="XST-PROBE-9f3a2b"

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
    GET=$(printf "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" | nc -w 5 "$HOST" "$PORT" 2>/dev/null)
    if echo "$GET" | head -1 | grep -q " 200"; then UP=1; break; fi
    sleep 1
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: Apache did not answer a normal GET with 200 on port $PORT —" >&2
    echo "                   service is down or broken." >&2
    exit 1
fi

###############################################################################
# PoC: send a TRACE request with a marker header against the LIVE server.
###############################################################################
TRACE=$(printf "TRACE / HTTP/1.1\r\nHost: localhost\r\nX-Xst-Probe: %s\r\nConnection: close\r\n\r\n" "$MARKER" | nc -w 5 "$HOST" "$PORT" 2>/dev/null)
STATUS=$(echo "$TRACE" | head -1)

if echo "$STATUS" | grep -q " 200" && echo "$TRACE" | grep -q "$MARKER"; then
    echo "FAIL [PoC]: TRACE returned 200 and echoed the request marker back —" >&2
    echo "            Cross-Site Tracing (XST) works. Still vulnerable." >&2
    echo "            status: $STATUS" >&2
    exit 1
fi
echo "PASS [PoC]: TRACE did not echo the request (status: $STATUS) — XST blocked."

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
