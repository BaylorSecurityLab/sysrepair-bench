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

# --- PoC Behavioral Test: skip-grant-tables should be gone at runtime ---
# If mysqld is running, verify skip-grant-tables is not active by attempting
# unauthenticated access — should fail if auth is enforced
if pgrep -x mysqld > /dev/null 2>&1; then
    SKIP_GRANT_TEST=$(mysql -u root --skip-password -e "SELECT 1" 2>/dev/null && echo "ok" || echo "denied")
    if [[ "$SKIP_GRANT_TEST" == "ok" ]]; then
        # This could mean skip-grant-tables is active OR root has no password.
        # Check more specifically: try an obviously-wrong password
        WRONG_PW_TEST=$(mysql -u root -p'__wrong_pw_verify__' -e "SELECT 1" 2>/dev/null && echo "ok" || echo "denied")
        if [[ "$WRONG_PW_TEST" == "ok" ]]; then
            echo "FAIL [PoC]: MySQL accepts any credentials — skip-grant-tables likely still active"
            PASS=false
        else
            echo "PASS [PoC]: MySQL root can connect without password but rejects wrong passwords (auth is enforced)"
        fi
    else
        echo "PASS [PoC]: Unauthenticated MySQL access denied (skip-grant-tables is off)"
    fi
fi

# --- PoC Behavioral Test: Verify bind address at runtime ---
LISTEN_ADDR=$(ss -tlnp 2>/dev/null | grep ':3306' || true)
if echo "$LISTEN_ADDR" | grep -qE '0\.0\.0\.0:3306|\*:3306'; then
    echo "FAIL [PoC]: MySQL is listening on 0.0.0.0:3306 at runtime"
    PASS=false
elif [ -n "$LISTEN_ADDR" ]; then
    echo "PASS [PoC]: MySQL is bound to a restricted address at runtime"
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
