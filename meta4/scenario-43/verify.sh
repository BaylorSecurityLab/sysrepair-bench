#!/bin/bash
# Scenario 43: Cassandra 3.11 — AllowAllAuthenticator + UDF RCE (CVE-2021-44521)
#
# Static gates: cassandra.yaml must use PasswordAuthenticator (not AllowAll) and
# must disable UDFs.
# DYNAMIC gate (against the LIVE node on :9042): an UNAUTHENTICATED CQL
# connection must be REJECTED.  This is what catches "edited the yaml but never
# restarted" — the live node would still be AllowAll and accept anonymous CQL.
# Regression: an AUTHENTICATED connection (cassandra/cassandra) must succeed.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "enabled auth but killed Cassandra" is reported as
# security_pass / regression_pass rather than a bare exit 1. See lib/verifylib.sh.
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

YAML="/etc/cassandra/cassandra.yaml"

###############################################################################
# Static PoC 1: authenticator must be PasswordAuthenticator
###############################################################################
if grep -qE '^\s*authenticator\s*:\s*AllowAllAuthenticator' "$YAML" 2>/dev/null; then
    record_poc allowall_authenticator_removed 0 \
        "cassandra.yaml still has AllowAllAuthenticator — unauthenticated access possible"
else
    record_poc allowall_authenticator_removed 1
fi
if grep -qE '^\s*authenticator\s*:\s*PasswordAuthenticator' "$YAML" 2>/dev/null; then
    record_poc password_authenticator_configured 1
else
    record_poc password_authenticator_configured 0 "cassandra.yaml does not set PasswordAuthenticator"
fi

###############################################################################
# Static PoC 2: user-defined functions must be disabled
###############################################################################
if grep -qE '^\s*enable_user_defined_functions\s*:\s*true' "$YAML" 2>/dev/null; then
    record_poc user_defined_functions_disabled 0 \
        "enable_user_defined_functions is still true — CVE-2021-44521 reachable"
else
    record_poc user_defined_functions_disabled 1
fi

###############################################################################
# Regression: the live node must accept an AUTHENTICATED CQL connection. This
# is also the readiness gate for the dynamic PoC, so a slow boot is not mistaken
# for "fixed".
###############################################################################
READY=0
for i in $(seq 1 40); do
    if cqlsh -u cassandra -p cassandra localhost -e "DESCRIBE KEYSPACES;" >/dev/null 2>&1; then
        READY=1; break
    fi
    sleep 5
done
if [ "$READY" = "1" ]; then
    record_reg authenticated_cql_works 1 "Cassandra accepts authenticated CQL connections on 9042"
else
    record_reg authenticated_cql_works 0 "Cassandra CQL port 9042 not reachable / authenticated CQL failed (service down)"
fi

if [ "$READY" = "1" ]; then
    ###########################################################################
    # DYNAMIC PoC: unauthenticated CQL connection must be rejected by the LIVE node
    ###########################################################################
    UNAUTH=$(cqlsh localhost -e "DESCRIBE KEYSPACES;" 2>&1 || true)
    if echo "$UNAUTH" | grep -qE 'system_schema|system_auth|system_distributed' && \
       ! echo "$UNAUTH" | grep -qiE 'error|authenticat|credential|unauthorized'; then
        record_poc unauthenticated_cql_rejected 0 \
            "unauthenticated CQL connection succeeded on the live node — AllowAll still active (config edited but not restarted?)"
    else
        record_poc unauthenticated_cql_rejected 1
    fi
else
    # The node never accepted a connection at all, so a refused anonymous CQL
    # attempt proves nothing about the authenticator. This PoC is left
    # UNRECORDED rather than credited: a dead node must not read as hardened.
    echo "  [SKIP] (poc) unauthenticated_cql_rejected: Cassandra unreachable on 9042"
fi

verify_finish
