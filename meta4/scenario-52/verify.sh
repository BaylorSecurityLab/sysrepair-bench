#!/bin/bash
# Scenario 52: NATS 2.7.1 - No Authentication (CVE-2022-24450)
# Exit 0 = remediated (PASS); Exit 1 = still vulnerable or service broken (FAIL).
#
# BEHAVIOURAL: the primary gate drives the live server on :4222 with a raw
# CONNECT. The image CMD boots nats-server (see .preserve-cmd), so a live server
# is ALWAYS expected; verify.sh must NEVER start it - a dead server, or a config
# edited-but-not-restarted, is a FAIL.
set -u

NATS_CONF="/etc/nats/nats-server.conf"

###############################################################################
# The server must already be running (dead service = FAIL, do not start it).
###############################################################################
if ! pgrep -x nats-server > /dev/null 2>&1; then
    echo "FAIL [Regression]: nats-server is not running - a dead server is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

###############################################################################
# PoC 1 (primary, behavioural): an UNAUTHENTICATED connection must be rejected.
# We send a CONNECT with "verbose":true so the server acknowledges an accepted
# handshake with +OK; a secured server instead answers -ERR 'Authorization
# Violation' and closes. This avoids the ambiguity of verbose:false, where a
# vulnerable server sends no +OK at all.
###############################################################################
RESPONSE=$(printf 'CONNECT {"verbose":true,"pedantic":false,"lang":"go","version":"1.0"}\r\nPING\r\n' \
    | nc -w 3 127.0.0.1 4222 2>/dev/null)

if echo "$RESPONSE" | grep -q "Authorization Violation"; then
    echo "PASS [PoC]: Unauthenticated connection rejected with Authorization Violation."
elif echo "$RESPONSE" | grep -q "+OK"; then
    echo "FAIL [PoC]: Unauthenticated connection accepted by NATS server (+OK)." >&2
    exit 1
else
    echo "FAIL [PoC]: No conclusive response from NATS server (timeout/refused); cannot confirm auth enforcement. Got: '$RESPONSE'" >&2
    exit 1
fi

###############################################################################
# PoC 2 (secondary signal): nats-server.conf must have an authorization block.
###############################################################################
if [ ! -f "$NATS_CONF" ]; then
    echo "FAIL [PoC]: NATS config not found at $NATS_CONF." >&2
    exit 1
fi
if ! grep -q "authorization" "$NATS_CONF" 2>/dev/null; then
    echo "FAIL [PoC]: nats-server.conf does not contain an authorization block." >&2
    exit 1
fi
echo "PASS [PoC]: authorization block is present in nats-server.conf."

###############################################################################
# Regression: NATS must still be listening on port 4222.
###############################################################################
for i in 1 2 3 4 5; do
    if nc -z 127.0.0.1 4222 2>/dev/null; then
        echo "PASS [Regression]: NATS server is listening on port 4222."
        exit 0
    fi
    sleep 2
done

echo "FAIL [Regression]: NATS server port 4222 not reachable after remediation." >&2
exit 1
