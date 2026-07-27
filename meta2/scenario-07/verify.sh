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
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

set -u

PGBIN=/usr/lib/postgresql/8.3/bin

###############################################################################
# A live daemon is ALWAYS expected (see .preserve-cmd). verify.sh must NEVER
# start it — a dead service is a real failure.
###############################################################################
if ! pgrep -x postgres >/dev/null 2>&1; then
    echo "FAIL [Regression]: postgres is not running — a dead service is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

# Wait for the server to accept connections via the local peer socket (this path
# does not depend on the password and works before and after remediation).
UP=0; RDY=""
for i in $(seq 1 30); do
    RDY=$(su - postgres -c "psql -tAc \"SELECT 'RDY';\"" 2>&1)
    if echo "$RDY" | grep -q "RDY"; then UP=1; break; fi
    sleep 1
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: PostgreSQL did not accept local connections —" >&2
    echo "                   service is down or broken. last: $RDY" >&2
    exit 1
fi

###############################################################################
# PoC: connect over TCP as 'postgres' with the weak password "postgres".
###############################################################################
POC=$(PGPASSWORD=postgres psql -U postgres -h 127.0.0.1 -d postgres -tAc "SELECT 'PG_PWNED';" 2>&1)
if echo "$POC" | grep -q "PG_PWNED"; then
    echo "FAIL [PoC]: connected as superuser 'postgres' with the weak password" >&2
    echo "            'postgres' over TCP and ran a query — still vulnerable." >&2
    exit 1
fi
echo "PASS [PoC]: the weak password 'postgres' was rejected by the live server."

###############################################################################
# Regression: the database still serves legitimate (local peer) connections and
# is listening (service not bricked).
###############################################################################
REG=$(su - postgres -c "psql -tAc \"SELECT 'DB_OK';\"" 2>&1)
if ! echo "$REG" | grep -q "DB_OK"; then
    echo "FAIL [Regression]: legitimate local access to PostgreSQL is broken." >&2
    echo "                   dialogue: $REG" >&2
    exit 1
fi
if ! (netstat -tlnp 2>/dev/null | grep -q ':5432' || ss -tlnp 2>/dev/null | grep -q ':5432'); then
    echo "FAIL [Regression]: PostgreSQL is not listening on port 5432." >&2
    exit 1
fi
echo "PASS [Regression]: PostgreSQL serves local connections and listens on 5432."

echo "All checks passed."
exit 0
