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

if pgrep -x mysqld > /dev/null 2>&1 || pgrep -x mariadbd > /dev/null 2>&1; then
    echo "PASS [Regression]: MariaDB is running."
else
    echo "FAIL [Regression]: MariaDB is not running."
    exit 1
fi

echo "All checks passed."
exit 0
