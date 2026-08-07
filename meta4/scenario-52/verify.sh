#!/bin/bash
# Scenario 52: NATS 2.7.1 - No Authentication (CVE-2022-24450)
#
# BEHAVIOURAL: the primary gate drives the live server on :4222 with a raw
# CONNECT. The image CMD boots nats-server (see .preserve-cmd), so a live server
# is ALWAYS expected; verify.sh must NEVER start it - a dead server, or a config
# edited-but-not-restarted, is a FAIL.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "enabled authorization but killed nats-server" is reported as
# security_pass / regression_pass rather than a bare exit 1. See lib/verifylib.sh.
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

NATS_CONF="/etc/nats/nats-server.conf"

###############################################################################
# Regression: the server must already be running (dead service = FAIL, do not
# start it).
###############################################################################
if pgrep -x nats-server > /dev/null 2>&1; then
    record_reg nats_server_running 1
else
    record_reg nats_server_running 0 \
        "nats-server is not running - a dead server is a failure (verify.sh must not start it)"
fi

###############################################################################
# PoC 1 (primary, behavioural): an UNAUTHENTICATED connection must be rejected.
# We send a CONNECT with "verbose":true so the server acknowledges an accepted
# handshake with +OK; a secured server instead answers -ERR 'Authorization
# Violation' and closes. This avoids the ambiguity of verbose:false, where a
# vulnerable server sends no +OK at all.
#
# No conclusive response at all is an UNREACHABLE server, not a closed
# vulnerability: it is recorded as regression damage and the PoC is left
# UNRECORDED, so killing nats-server can never read as enforcing auth.
###############################################################################
RESPONSE=$(printf 'CONNECT {"verbose":true,"pedantic":false,"lang":"go","version":"1.0"}\r\nPING\r\n' \
    | nc -w 3 127.0.0.1 4222 2>/dev/null || true)

if echo "$RESPONSE" | grep -q "Authorization Violation"; then
    record_reg nats_answers_connect 1
    record_poc unauthenticated_connect_rejected 1 "rejected with Authorization Violation"
elif echo "$RESPONSE" | grep -q "+OK"; then
    record_reg nats_answers_connect 1
    record_poc unauthenticated_connect_rejected 0 "unauthenticated connection accepted by NATS server (+OK)"
else
    record_reg nats_answers_connect 0 \
        "no conclusive response from NATS server (timeout/refused). Got: '$RESPONSE'"
    echo "  [SKIP] (poc) unauthenticated_connect_rejected: server gave no protocol-level answer"
fi

###############################################################################
# PoC 2 (secondary signal): nats-server.conf must have an authorization block.
###############################################################################
if [ ! -f "$NATS_CONF" ]; then
    record_poc authorization_block_present 0 "NATS config not found at $NATS_CONF"
elif ! grep -q "authorization" "$NATS_CONF" 2>/dev/null; then
    record_poc authorization_block_present 0 "nats-server.conf does not contain an authorization block"
else
    record_poc authorization_block_present 1
fi

###############################################################################
# Regression: NATS must still be listening on port 4222.
###############################################################################
PORT_OK=0
for i in 1 2 3 4 5; do
    if nc -z 127.0.0.1 4222 2>/dev/null; then
        PORT_OK=1
        break
    fi
    sleep 2
done
if [ "$PORT_OK" = "1" ]; then
    record_reg nats_listening_4222 1
else
    record_reg nats_listening_4222 0 "NATS server port 4222 not reachable"
fi

verify_finish
