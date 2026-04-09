#!/bin/bash
# Verification: Scenario 24 - MySQL FILE/SUPER Privileges (Symfonos 2)
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable (FAIL)

# Start MariaDB if not running
if ! pgrep -x mysqld > /dev/null 2>&1 && ! pgrep -x mariadbd > /dev/null 2>&1; then
    mysqld & sleep 3
fi

GRANTS=$(mysql -N -e "SHOW GRANTS FOR 'webapp'@'localhost';" 2>/dev/null)
if [ -z "$GRANTS" ]; then
    echo "FAIL [PoC]: Cannot connect to MariaDB to check grants."
    exit 1
fi

if echo "$GRANTS" | grep -qi 'FILE'; then
    echo "FAIL [PoC]: webapp user still has FILE privilege."
    exit 1
fi

if echo "$GRANTS" | grep -qi 'SUPER'; then
    echo "FAIL [PoC]: webapp user still has SUPER privilege."
    exit 1
fi

echo "PASS [PoC]: webapp user has no dangerous privileges."
echo "All checks passed."
exit 0
