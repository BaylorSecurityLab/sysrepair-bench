#!/bin/bash
# Verification script for Scenario 06: MySQL Root Empty Password
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

###############################################################################
# PoC Check: Ensure MySQL root login with empty password fails
###############################################################################

# Ensure MySQL is running for the test
if ! pgrep -x mysqld > /dev/null 2>&1; then
    /etc/init.d/mysql start > /dev/null 2>&1
    sleep 3
fi

# Attempt to login as root with no password
RESULT=$(mysql -u root -e "SELECT 1;" 2>&1)

if echo "$RESULT" | grep -q "1"; then
    echo "FAIL [PoC]: MySQL root login with empty password still succeeds."
    exit 1
fi

echo "PASS [PoC]: MySQL root login with empty password is denied."

# Check bind-address is restricted to localhost
MY_CNF="/etc/mysql/my.cnf"
BIND_ADDR=$(grep -i '^bind-address' "$MY_CNF" 2>/dev/null | tail -1 | sed 's/.*=\s*//' | tr -d ' ')

if [ "$BIND_ADDR" = "0.0.0.0" ] || [ "$BIND_ADDR" = "*" ]; then
    echo "FAIL [PoC]: MySQL bind-address is still set to $BIND_ADDR (listening on all interfaces)."
    exit 1
elif [ -z "$BIND_ADDR" ]; then
    echo "WARN [PoC]: No bind-address directive found. MySQL may be listening on all interfaces."
else
    echo "PASS [PoC]: MySQL bind-address is set to $BIND_ADDR."
fi

###############################################################################
# Regression Check: Ensure MySQL is running and functional
###############################################################################

# Check if mysqld process is running
if pgrep -x mysqld > /dev/null 2>&1; then
    echo "PASS [Regression]: mysqld process is running."
else
    # Try to start MySQL and check again
    /etc/init.d/mysql start > /dev/null 2>&1
    sleep 3
    if pgrep -x mysqld > /dev/null 2>&1; then
        echo "PASS [Regression]: mysqld process started and is running."
    else
        echo "FAIL [Regression]: mysqld is not running. Service may be broken."
        exit 1
    fi
fi

# Verify MySQL is listening on port 3306
if netstat -tlnp 2>/dev/null | grep -q ':3306'; then
    echo "PASS [Regression]: mysqld is listening on port 3306."
else
    echo "FAIL [Regression]: mysqld is not listening on port 3306."
    exit 1
fi

echo "All checks passed."
exit 0
