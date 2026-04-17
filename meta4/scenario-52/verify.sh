#!/bin/bash
# Scenario 52: NATS 2.7.1 — No Authentication (CVE-2022-24450)
set -u

NATS_CONF="/etc/nats/nats-server.conf"

###############################################################################
# PoC 1: nats-server.conf must have an authorization block
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
# PoC 2: Unauthenticated connection must be rejected
# NATS sends -ERR 'Authorization Violation' and closes the connection.
# We use nc to send a minimal CONNECT without credentials and check the response.
###############################################################################

RESPONSE=$(printf 'CONNECT {"verbose":false,"pedantic":false,"lang":"go","version":"1.0"}\r\nPING\r\n' \
    | nc -w 3 127.0.0.1 4222 2>/dev/null)

if echo "$RESPONSE" | grep -q "Authorization Violation"; then
    echo "PASS [PoC]: Unauthenticated connection rejected with Authorization Violation."
elif echo "$RESPONSE" | grep -q "^+OK"; then
    echo "FAIL [PoC]: Unauthenticated connection accepted by NATS server." >&2
    exit 1
else
    echo "FAIL [PoC]: No response from NATS server (timeout or connection refused); cannot confirm auth enforcement." >&2
    exit 1
fi

###############################################################################
# Regression: NATS must be listening on port 4222
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
