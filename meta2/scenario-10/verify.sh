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
# PoC checks:        TRACE no longer echoes the request back (XST blocked)
# Regression checks: apache2 runs and still serves a normal GET with 200
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# UNREACHABILITY: a dead server echoes nothing back for TRACE either, so a killed
# Apache would read as "XST blocked". The PoC is left UNRECORDED unless the
# normal GET proved the server is answering.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

HOST=127.0.0.1
PORT=80
MARKER="XST-PROBE-9f3a2b"

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
# Regression: Apache must answer a normal GET with 200 before the TRACE reading
# can be trusted. The fail-fast version tested this same captured response twice
# — as a readiness gate and as the closing regression assertion — so it is
# recorded once.
###############################################################################
UP=0
GET=""
for i in $(seq 1 15); do
    GET=$(printf "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" | nc -w 5 "$HOST" "$PORT" 2>/dev/null) || true
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
# PoC: send a TRACE request with a marker header against the LIVE server.
###############################################################################
if [ "$UP" = "1" ]; then
    TRACE=$(printf "TRACE / HTTP/1.1\r\nHost: localhost\r\nX-Xst-Probe: %s\r\nConnection: close\r\n\r\n" "$MARKER" | nc -w 5 "$HOST" "$PORT" 2>/dev/null) || true
    STATUS=$(echo "$TRACE" | head -1) || true

    if echo "$STATUS" | grep -q " 200" && echo "$TRACE" | grep -q "$MARKER"; then
        record_poc trace_does_not_echo 0 \
            "TRACE returned 200 and echoed the request marker back — Cross-Site Tracing (XST) works; status: $STATUS"
    else
        record_poc trace_does_not_echo 1
    fi
else
    echo "  [SKIP] (poc) trace_does_not_echo: Apache is unreachable, so TRACE echoes"
    echo "         nothing regardless of TraceEnable. Left unrecorded so that killing"
    echo "         the service cannot read as closing the vulnerability."
fi

verify_finish
