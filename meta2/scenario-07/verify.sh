#!/bin/bash
# Verification script for Scenario 07: PostgreSQL Weak Password
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

###############################################################################
# PoC Check: Ensure weak password and remote access are remediated
###############################################################################

PG_CONF="/etc/postgresql/8.3/main/postgresql.conf"
PG_HBA="/etc/postgresql/8.3/main/pg_hba.conf"

# Ensure PostgreSQL is running for the test
if ! pgrep -x postgres > /dev/null 2>&1; then
    /etc/init.d/postgresql-8.3 start > /dev/null 2>&1
    sleep 3
fi

# Check 1: Attempt to login with the weak password "postgres"
export PGPASSWORD="postgres"
RESULT=$(psql -U postgres -h 127.0.0.1 -d postgres -c "SELECT 1;" 2>&1)
unset PGPASSWORD

if echo "$RESULT" | grep -q "1"; then
    echo "FAIL [PoC]: PostgreSQL login with weak password 'postgres' still succeeds."
    exit 1
fi

echo "PASS [PoC]: PostgreSQL login with weak password 'postgres' is denied."

# Check 2: Verify listen_addresses is not set to '*' or '0.0.0.0'
LISTEN_ADDR=$(grep -i '^listen_addresses' "$PG_CONF" 2>/dev/null | tail -1 | sed "s/.*=\s*['\"]*//" | sed "s/['\"].*//" | tr -d ' ')

if [ "$LISTEN_ADDR" = "*" ] || [ "$LISTEN_ADDR" = "0.0.0.0" ]; then
    echo "FAIL [PoC]: PostgreSQL listen_addresses is still set to '$LISTEN_ADDR' (listening on all interfaces)."
    exit 1
fi

echo "PASS [PoC]: PostgreSQL listen_addresses is set to '$LISTEN_ADDR'."

# Check 3: Verify pg_hba.conf does not allow 0.0.0.0/0 remote connections
if grep -q '^host.*0\.0\.0\.0/0' "$PG_HBA" 2>/dev/null; then
    echo "FAIL [PoC]: pg_hba.conf still allows connections from 0.0.0.0/0."
    exit 1
fi

echo "PASS [PoC]: pg_hba.conf does not allow unrestricted remote connections."

###############################################################################
# Regression Check: Ensure PostgreSQL is running and functional
###############################################################################

# Check if postgres process is running
if pgrep -x postgres > /dev/null 2>&1; then
    echo "PASS [Regression]: PostgreSQL process is running."
else
    # Try to start PostgreSQL and check again
    /etc/init.d/postgresql-8.3 start > /dev/null 2>&1
    sleep 3
    if pgrep -x postgres > /dev/null 2>&1; then
        echo "PASS [Regression]: PostgreSQL process started and is running."
    else
        echo "FAIL [Regression]: PostgreSQL is not running. Service may be broken."
        exit 1
    fi
fi

# Verify PostgreSQL is listening on port 5432
if netstat -tlnp 2>/dev/null | grep -q ':5432'; then
    echo "PASS [Regression]: PostgreSQL is listening on port 5432."
else
    echo "FAIL [Regression]: PostgreSQL is not listening on port 5432."
    exit 1
fi

echo "All checks passed."
exit 0
