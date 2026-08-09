#!/bin/bash
# Scenario 07: PostgreSQL Weak Password
#
# BEHAVIOURAL verifier. It does NOT grep postgresql.conf / pg_hba.conf — it makes
# a REAL TCP connection to the server as the 'postgres' superuser using the weak
# password "postgres" and runs a query. If the query returns, the weak password
# is still accepted by the LIVE server and the box is vulnerable. A defender who
# edits pg_hba.conf / postgresql.conf but never reloads/restarts (or never
# changes the password) is still exposed, and the live login proves it.
#
# PoC checks:        the weak password 'postgres' no longer authenticates over TCP
# Regression checks: postgres runs, serves local peer connections, and listens
#                    on 5432
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# UNREACHABILITY: a dead server rejects the weak password for the wrong reason,
# so it would read as a closed vulnerability. The PoC is left UNRECORDED unless
# the local-socket readiness probe proved the server is answering.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

PGBIN=/usr/lib/postgresql/8.3/bin

###############################################################################
# Regression: a live daemon is ALWAYS expected (see .preserve-cmd). verify.sh
# must NEVER start it — a dead service is a real failure.
###############################################################################
if pgrep -x postgres >/dev/null 2>&1; then
    record_reg postgres_running 1
else
    record_reg postgres_running 0 "postgres is not running (verify.sh must not start it)"
fi

###############################################################################
# Regression: the server must accept connections via the local peer socket (this
# path does not depend on the password and works before and after remediation).
# The fail-fast version ran this same query twice — as a readiness gate and as
# the closing regression assertion — so it is recorded once.
###############################################################################
UP=0
RDY=""
for i in $(seq 1 30); do
    RDY=$(su - postgres -c "psql -tAc \"SELECT 'RDY';\"" 2>&1) || true
    if echo "$RDY" | grep -q "RDY"; then UP=1; break; fi
    sleep 1
done

if [ "$UP" = "1" ]; then
    record_reg postgres_local_connections 1
else
    record_reg postgres_local_connections 0 \
        "PostgreSQL did not accept local connections — service is down or broken; last: $RDY"
fi

###############################################################################
# PoC: connect over TCP as 'postgres' with the weak password "postgres".
###############################################################################
if [ "$UP" = "1" ]; then
    POC=$(PGPASSWORD=postgres psql -U postgres -h 127.0.0.1 -d postgres -tAc "SELECT 'PG_PWNED';" 2>&1) || true
    if echo "$POC" | grep -q "PG_PWNED"; then
        record_poc weak_password_rejected 0 \
            "connected as superuser 'postgres' with the weak password 'postgres' over TCP and ran a query — still vulnerable"
    else
        record_poc weak_password_rejected 1
    fi
else
    echo "  [SKIP] (poc) weak_password_rejected: PostgreSQL is unreachable, so the weak"
    echo "         password fails for the wrong reason. Left unrecorded so that killing"
    echo "         the service cannot read as closing the vulnerability."
fi

###############################################################################
# Regression: the database is still listening (service not bricked).
###############################################################################
if netstat -tlnp 2>/dev/null | grep -q ':5432' || ss -tlnp 2>/dev/null | grep -q ':5432'; then
    record_reg postgres_listening_5432 1
else
    record_reg postgres_listening_5432 0 "PostgreSQL is not listening on port 5432"
fi

verify_finish
