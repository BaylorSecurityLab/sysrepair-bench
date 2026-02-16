#!/bin/bash
# Verification script for Scenario 13: phpinfo() Exposed
# Check 1 (PoC): /phpinfo.php should NOT be accessible (expect 404 or 403)
# Check 2 (Regression): PHP should still work on Apache

##############################################################################
# Ensure Apache is running for the checks
##############################################################################
apache2ctl start 2>/dev/null
sleep 1

##############################################################################
# PoC Check: phpinfo.php should not be accessible
##############################################################################

PHPINFO_RESPONSE=$(printf "GET /phpinfo.php HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" | \
    nc -w 5 127.0.0.1 80 2>/dev/null)

PHPINFO_STATUS=$(echo "$PHPINFO_RESPONSE" | head -1)

if echo "$PHPINFO_STATUS" | grep -qE "200 OK"; then
    # Got 200 -- check if it actually contains phpinfo output
    if echo "$PHPINFO_RESPONSE" | grep -qi "phpinfo\|PHP Version\|PHP License"; then
        echo "FAIL: phpinfo.php is accessible and exposes PHP configuration."
        exit 1
    else
        echo "PASS: /phpinfo.php returns 200 but does not contain phpinfo output."
    fi
elif echo "$PHPINFO_STATUS" | grep -qE "404|403"; then
    echo "PASS: phpinfo.php is not accessible (got: $PHPINFO_STATUS)."
else
    # Fallback: check if the file still exists on disk
    if [ -f /var/www/phpinfo.php ]; then
        if grep -q 'phpinfo' /var/www/phpinfo.php 2>/dev/null; then
            echo "FAIL: phpinfo.php still exists in web root with phpinfo() call."
            exit 1
        else
            echo "PASS: phpinfo.php exists but no longer contains phpinfo()."
        fi
    else
        echo "PASS: phpinfo.php has been removed from web root."
    fi
fi

##############################################################################
# Regression Check: PHP should still work on Apache
##############################################################################

PHP_RESPONSE=$(printf "GET /test.php HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" | \
    nc -w 5 127.0.0.1 80 2>/dev/null)

if echo "$PHP_RESPONSE" | grep -q "PHP is working"; then
    echo "PASS: PHP is functioning correctly on Apache."
else
    # Fallback: check if Apache and PHP module are running
    if pgrep -x apache2 > /dev/null 2>&1; then
        if apache2ctl -M 2>/dev/null | grep -q 'php'; then
            echo "PASS: Apache is running with PHP module loaded."
        else
            echo "FAIL: PHP module is not loaded in Apache."
            exit 1
        fi
    else
        echo "FAIL: Apache is not running."
        exit 1
    fi
fi

echo "All checks passed."
exit 0
