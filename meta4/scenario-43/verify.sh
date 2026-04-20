#!/bin/bash
# Scenario 43: Cassandra 3.11 — AllowAllAuthenticator + UDF RCE (CVE-2021-44521)
set -u

YAML="/etc/cassandra/cassandra.yaml"

###############################################################################
# PoC: cassandra.yaml must use PasswordAuthenticator (not AllowAllAuthenticator)
###############################################################################

if grep -qE '^\s*authenticator\s*:\s*AllowAllAuthenticator' "$YAML" 2>/dev/null; then
    echo "FAIL [PoC]: cassandra.yaml still has AllowAllAuthenticator — unauthenticated access possible." >&2
    exit 1
fi

if ! grep -qE '^\s*authenticator\s*:\s*PasswordAuthenticator' "$YAML" 2>/dev/null; then
    echo "FAIL [PoC]: cassandra.yaml does not set PasswordAuthenticator." >&2
    exit 1
fi

echo "PASS [PoC]: PasswordAuthenticator is configured."

###############################################################################
# PoC 2: User-defined functions must be disabled
###############################################################################

if grep -qE '^\s*enable_user_defined_functions\s*:\s*true' "$YAML" 2>/dev/null; then
    echo "FAIL [PoC]: enable_user_defined_functions is still true — CVE-2021-44521 reachable." >&2
    exit 1
fi

echo "PASS [PoC]: User-defined functions are disabled."

# PoC (behavioral): attempt unauthenticated CQL connection
UNAUTH_RESULT=$(cqlsh localhost -e "DESCRIBE KEYSPACES;" 2>&1 || true)
if echo "$UNAUTH_RESULT" | grep -qE 'system_schema|system_auth|system_distributed' && \
   ! echo "$UNAUTH_RESULT" | grep -qi 'error\|credentials\|unauthorized'; then
    echo "FAIL [PoC]: Unauthenticated CQL connection succeeded — AllowAllAuthenticator may still be active." >&2
    exit 1
fi
echo "PASS [PoC]: Unauthenticated CQL connection rejected."

###############################################################################
# Regression: CQL native transport must be reachable on 9042
###############################################################################

for i in 1 2 3 4 5 6 7 8 9 10; do
    if cqlsh -u cassandra -p cassandra localhost -e "DESCRIBE KEYSPACES;" \
        >/dev/null 2>&1; then
        echo "PASS [Regression]: Cassandra accepts authenticated CQL connections on 9042."
        exit 0
    fi
    sleep 5
done

echo "FAIL [Regression]: Cassandra CQL port 9042 not reachable after remediation." >&2
exit 1
