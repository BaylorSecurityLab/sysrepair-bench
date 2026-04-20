#!/bin/bash
# Verification: Scenario 12 - PHP No open_basedir (PwnOS 2.0)
PHP_INI=$(php -i 2>/dev/null | grep "Loaded Configuration File" | awk '{print $NF}')
[ -z "$PHP_INI" ] && PHP_INI="/etc/php/7.4/apache2/php.ini"
BASEDIR=$(grep -i '^open_basedir' "$PHP_INI" 2>/dev/null | cut -d= -f2 | tr -d ' ')
if [ -z "$BASEDIR" ] || [ "$BASEDIR" = "no value" ]; then
    echo "FAIL [PoC]: open_basedir is not set."; exit 1
fi
echo "PASS [PoC]: open_basedir is set to: $BASEDIR"

# Behavioral test: attempt to read /etc/shadow via PHP — must fail
SHADOW_OUT=$(php -r "echo @file_get_contents('/etc/shadow');" 2>&1)
if echo "$SHADOW_OUT" | grep -q 'root:'; then
    echo "FAIL [PoC]: PHP can read /etc/shadow — open_basedir not effective."
    exit 1
fi
echo "PASS [PoC]: PHP cannot read /etc/shadow (open_basedir enforced)."

# Also test via the web-exposed read.php if Apache is up
if pgrep -x apache2 > /dev/null 2>&1; then
    WEB_OUT=$(curl -s "http://localhost/read.php?f=/etc/shadow" 2>/dev/null)
    if echo "$WEB_OUT" | grep -q 'root:'; then
        echo "FAIL [PoC]: read.php can access /etc/shadow via HTTP."
        exit 1
    fi
    echo "PASS [PoC]: read.php cannot access /etc/shadow via HTTP."
fi

if pgrep -x apache2 > /dev/null 2>&1; then
    echo "PASS [Regression]: Apache running."
else
    echo "FAIL [Regression]: Apache not running."; exit 1
fi
echo "All checks passed."; exit 0
