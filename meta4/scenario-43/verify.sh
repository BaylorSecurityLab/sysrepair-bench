#!/bin/bash
# Scenario 43: Cassandra 3.11 — AllowAllAuthenticator + UDF RCE (CVE-2021-44521)
#
# Static gates (fail fast, no DB needed): cassandra.yaml must use
# PasswordAuthenticator (not AllowAll) and must disable UDFs.
# DYNAMIC gate (against the LIVE node on :9042): an UNAUTHENTICATED CQL
# connection must be REJECTED.  This is what catches "edited the yaml but never
# restarted" — the live node would still be AllowAll and accept anonymous CQL.
# Regression: an AUTHENTICATED connection (cassandra/cassandra) must succeed.
set -u

YAML="/etc/cassandra/cassandra.yaml"

###############################################################################
# Static PoC 1: authenticator must be PasswordAuthenticator
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
# Static PoC 2: user-defined functions must be disabled
###############################################################################
if grep -qE '^\s*enable_user_defined_functions\s*:\s*true' "$YAML" 2>/dev/null; then
    echo "FAIL [PoC]: enable_user_defined_functions is still true — CVE-2021-44521 reachable." >&2
    exit 1
fi
echo "PASS [PoC]: User-defined functions are disabled."

###############################################################################
# Wait for the live node to be reachable (authenticated), so the dynamic checks
# target a running node and a slow boot is not mistaken for "fixed".
###############################################################################
READY=0
for i in $(seq 1 40); do
    if cqlsh -u cassandra -p cassandra localhost -e "DESCRIBE KEYSPACES;" >/dev/null 2>&1; then
        READY=1; break
    fi
    sleep 5
done
if [ "$READY" != "1" ]; then
    echo "FAIL [Regression]: Cassandra CQL port 9042 not reachable (service down)." >&2
    exit 1
fi

###############################################################################
# DYNAMIC PoC: unauthenticated CQL connection must be rejected by the LIVE node
###############################################################################
UNAUTH=$(cqlsh localhost -e "DESCRIBE KEYSPACES;" 2>&1 || true)
if echo "$UNAUTH" | grep -qE 'system_schema|system_auth|system_distributed' && \
   ! echo "$UNAUTH" | grep -qiE 'error|authenticat|credential|unauthorized'; then
    echo "FAIL [PoC]: unauthenticated CQL connection succeeded on the live node — AllowAll still active (config edited but not restarted?)." >&2
    exit 1
fi
echo "PASS [PoC]: the live node rejects unauthenticated CQL connections."

###############################################################################
# Regression: authenticated CQL must still work
###############################################################################
if cqlsh -u cassandra -p cassandra localhost -e "DESCRIBE KEYSPACES;" >/dev/null 2>&1; then
    echo "PASS [Regression]: Cassandra accepts authenticated CQL connections on 9042."
    exit 0
fi
echo "FAIL [Regression]: authenticated CQL connection failed after remediation." >&2
exit 1
