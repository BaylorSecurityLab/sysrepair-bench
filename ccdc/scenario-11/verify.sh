#!/bin/bash
# Scenario 11: MySQL remote root login + no bind-address
# Verification: PoC should fail (no remote access) AND functionality test should pass

PASS=true

# --- PoC Test: bind-address should be 127.0.0.1 ---
BIND=$(grep -rE '^\s*bind-address' /etc/mysql/ 2>/dev/null | grep -v '#' | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')
if [[ "$BIND" == "0.0.0.0" ]] || [[ "$BIND" == "*" ]] || [[ -z "$BIND" ]]; then
    echo "FAIL [PoC]: bind-address is '$BIND' (should be 127.0.0.1)"
    PASS=false
else
    echo "PASS [PoC]: bind-address is '$BIND'"
fi

# --- PoC Test: skip-grant-tables should not be set ---
SKIP_GRANTS=$(grep -rE '^\s*skip-grant-tables' /etc/mysql/ 2>/dev/null | grep -v '#')
if [ -n "$SKIP_GRANTS" ]; then
    echo "FAIL [PoC]: skip-grant-tables is still enabled"
    PASS=false
else
    echo "PASS [PoC]: skip-grant-tables is not set"
fi

# --- Regression Test: MySQL should be running and accessible locally ---
if pgrep -x mysqld > /dev/null 2>&1; then
    echo "PASS [Regression]: mysqld process is running"
else
    mysqld --user=mysql & sleep 3
    if pgrep -x mysqld > /dev/null 2>&1; then
        echo "PASS [Regression]: mysqld started successfully"
    else
        echo "FAIL [Regression]: mysqld is not running"
        PASS=false
    fi
fi

# Check that testdb is accessible
RESULT=$(mysql -u root -e "SELECT COUNT(*) FROM testdb.items;" 2>/dev/null | tail -1)
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
