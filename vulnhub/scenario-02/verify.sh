#!/bin/bash
# Verification script for Scenario 03: SQL Injection No WAF
# VulnHub Source: Kioptrix Level 1.1
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable (FAIL)

###############################################################################
# PoC Check: mod_security must be installed and active
###############################################################################

if ! dpkg -l | grep -q libapache2-mod-security2; then
    echo "FAIL [PoC]: libapache2-mod-security2 is not installed."
    exit 1
fi

echo "PASS [PoC]: mod_security is installed."

if ! apache2ctl -M 2>/dev/null | grep -qi security2; then
    echo "FAIL [PoC]: mod_security2 module is not loaded in Apache."
    exit 1
fi

echo "PASS [PoC]: mod_security2 module is loaded."

# Behavioral test: send a SQL injection payload — WAF must block it
SQLI_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost/search.php?q=1%20OR%201%3D1" 2>/dev/null)
if [ "$SQLI_CODE" = "200" ]; then
    echo "FAIL [PoC]: SQLi payload returned 200 — WAF did not block the request."
    exit 1
fi
echo "PASS [PoC]: SQLi payload blocked (HTTP $SQLI_CODE)."

# Check if the PHP script still has raw SQL concatenation
SEARCH_PHP="/var/www/html/search.php"
if [ -f "$SEARCH_PHP" ]; then
    if grep -q '\$_GET\|\\$_POST\|\\$_REQUEST' "$SEARCH_PHP" && grep -q '\..*\$' "$SEARCH_PHP" | grep -v 'prepare\|bindParam\|bind_param'; then
        echo "WARN [PoC]: PHP script may still contain raw SQL concatenation."
    fi
fi

###############################################################################
# Regression Check: Apache and MySQL running
###############################################################################

if pgrep -x apache2 > /dev/null 2>&1; then
    echo "PASS [Regression]: Apache is running."
else
    echo "FAIL [Regression]: Apache is not running."
    exit 1
fi

if pgrep -x mysqld > /dev/null 2>&1 || pgrep -x mariadbd > /dev/null 2>&1; then
    echo "PASS [Regression]: MySQL/MariaDB is running."
else
    echo "FAIL [Regression]: MySQL/MariaDB is not running."
    exit 1
fi

echo "All checks passed."
exit 0
