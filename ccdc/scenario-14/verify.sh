#!/bin/bash
# Scenario 14: PostgreSQL listen_addresses = '*' unprotected
# Verification: PoC should fail (localhost only) AND functionality test should pass

PASS=true

# Find postgresql.conf
PG_CONF=$(find /etc/postgresql -name postgresql.conf 2>/dev/null | head -1)

if [ -z "$PG_CONF" ]; then
    echo "FAIL [Regression]: postgresql.conf not found"
    PASS=false
else
    # --- PoC Test: listen_addresses should be localhost ---
    LISTEN=$(grep -E "^\s*listen_addresses" "$PG_CONF" | grep -v '#' | tail -1 | awk -F"'" '{print $2}')
    if [[ "$LISTEN" == "*" ]]; then
        echo "FAIL [PoC]: listen_addresses is still '*'"
        PASS=false
    elif [[ "$LISTEN" == "localhost" ]] || [[ "$LISTEN" == "127.0.0.1" ]]; then
        echo "PASS [PoC]: listen_addresses is '$LISTEN'"
    else
        echo "PASS [PoC]: listen_addresses is '$LISTEN' (not wildcard)"
    fi
fi

# --- PoC Behavioral Test: Verify PostgreSQL is not listening on all interfaces ---
# Ensure PostgreSQL is running for this test
if ! pgrep -x postgres > /dev/null 2>&1; then
    su -c "pg_ctlcluster $(pg_lsclusters -h | awk '{print $1, $2}') start" postgres 2>/dev/null
    sleep 2
fi

PG_LISTEN=$(ss -tlnp 2>/dev/null | grep ':5432' || true)
if echo "$PG_LISTEN" | grep -qE '0\.0\.0\.0:5432|\*:5432'; then
    echo "FAIL [PoC]: PostgreSQL is listening on 0.0.0.0:5432 at runtime"
    PASS=false
elif [ -n "$PG_LISTEN" ]; then
    echo "PASS [PoC]: PostgreSQL is bound to a restricted address at runtime"
else
    echo "INFO [PoC]: PostgreSQL port 5432 not detected in ss output (service may not be running)"
fi

# --- Regression Test: PostgreSQL should be running and accessible locally ---
if pgrep -x postgres > /dev/null 2>&1; then
    echo "PASS [Regression]: PostgreSQL is running"
else
    su -c "pg_ctlcluster $(pg_lsclusters -h | awk '{print $1, $2}') start" postgres 2>/dev/null
    sleep 2
    if pgrep -x postgres > /dev/null 2>&1; then
        echo "PASS [Regression]: PostgreSQL started successfully"
    else
        echo "FAIL [Regression]: PostgreSQL is not running"
        PASS=false
    fi
fi

RESULT=$(su -c "psql -d testdb -t -c 'SELECT COUNT(*) FROM items;'" postgres 2>/dev/null | tr -d ' ')
if [[ "$RESULT" -ge 1 ]] 2>/dev/null; then
    echo "PASS [Regression]: testdb is accessible and has data"
else
    echo "FAIL [Regression]: testdb is not accessible or has no data"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
