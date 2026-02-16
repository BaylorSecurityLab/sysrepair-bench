#!/bin/bash
# Scenario 12: MySQL local-infile enabled
# Verification: PoC should fail (local-infile disabled) AND functionality test should pass

PASS=true

# --- PoC Test: local-infile should be disabled ---
LOCAL_INFILE=$(grep -rE '^\s*local-infile' /etc/mysql/ 2>/dev/null | grep -v '#' | grep '\[mysqld\]' -A 100 | grep 'local-infile' | head -1 | awk -F'=' '{print $2}' | tr -d ' ')
if [ -z "$LOCAL_INFILE" ]; then
    LOCAL_INFILE=$(grep -rE '^\s*local-infile' /etc/mysql/ 2>/dev/null | grep -v '#' | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')
fi

if [[ "$LOCAL_INFILE" == "1" ]] || [[ "$LOCAL_INFILE" == "ON" ]] || [[ "$LOCAL_INFILE" == "on" ]]; then
    echo "FAIL [PoC]: local-infile is still enabled ($LOCAL_INFILE)"
    PASS=false
else
    echo "PASS [PoC]: local-infile is disabled"
fi

# --- Regression Test: MySQL should be running and accessible ---
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
