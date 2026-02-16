#!/bin/bash
# Scenario 13: PostgreSQL pg_hba.conf trust all connections
# Verification: PoC should fail (no trust auth) AND functionality test should pass

PASS=true

# Find pg_hba.conf
PG_HBA=$(find /etc/postgresql -name pg_hba.conf 2>/dev/null | head -1)

if [ -z "$PG_HBA" ]; then
    echo "FAIL [Regression]: pg_hba.conf not found"
    PASS=false
else
    # --- PoC Test: No 'trust' authentication for host connections ---
    TRUST_HOST=$(grep -E '^\s*host\s+' "$PG_HBA" | grep -v '#' | grep 'trust')
    if [ -n "$TRUST_HOST" ]; then
        echo "FAIL [PoC]: trust authentication still exists for host connections"
        PASS=false
    else
        echo "PASS [PoC]: No trust authentication for host connections"
    fi

    # Check local connections too (trust on local is also dangerous)
    TRUST_LOCAL=$(grep -E '^\s*local\s+' "$PG_HBA" | grep -v '#' | grep 'trust')
    if [ -n "$TRUST_LOCAL" ]; then
        echo "FAIL [PoC]: trust authentication still exists for local connections"
        PASS=false
    else
        echo "PASS [PoC]: No trust authentication for local connections"
    fi
fi

# --- Regression Test: PostgreSQL should be running ---
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

# Check testdb is accessible
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
