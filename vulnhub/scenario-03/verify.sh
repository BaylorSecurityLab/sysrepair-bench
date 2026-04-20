#!/bin/bash
# Verification script for Scenario 06: MySQL No secure_file_priv
# VulnHub Source: Kioptrix Level 1.3
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable (FAIL)

PRIV=$(grep -r 'secure_file_priv' /etc/mysql/ 2>/dev/null | grep -v '^#' | tail -1)

if echo "$PRIV" | grep -q 'secure_file_priv=$' || echo "$PRIV" | grep -q 'secure_file_priv=""'; then
    echo "FAIL [PoC]: secure_file_priv is empty (unrestricted)."
    exit 1
fi

if echo "$PRIV" | grep -q 'secure_file_priv=/' ; then
    echo "PASS [PoC]: secure_file_priv is set to a restricted path."
else
    echo "FAIL [PoC]: secure_file_priv not properly configured."
    exit 1
fi

# Behavioral test: query the running server for the runtime value
RUNTIME_SFP=$(mysql -u root -N -e "SHOW VARIABLES LIKE 'secure_file_priv';" 2>/dev/null | awk '{print $2}')
if [ -z "$RUNTIME_SFP" ] || [ "$RUNTIME_SFP" = "NULL" ]; then
    echo "WARN [PoC]: Could not query runtime secure_file_priv (server may not be running yet)."
elif [ "$RUNTIME_SFP" = "" ]; then
    echo "FAIL [PoC]: Runtime secure_file_priv is empty (unrestricted)."
    exit 1
else
    echo "PASS [PoC]: Runtime secure_file_priv = $RUNTIME_SFP"
fi

if pgrep -x mysqld > /dev/null 2>&1 || pgrep -x mariadbd > /dev/null 2>&1; then
    echo "PASS [Regression]: MariaDB is running."
else
    echo "FAIL [Regression]: MariaDB is not running."
    exit 1
fi

echo "All checks passed."
exit 0
