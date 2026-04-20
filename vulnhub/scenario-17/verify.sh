#!/bin/bash
VHOST=$(find /etc/apache2 /etc/httpd -name "*.conf" 2>/dev/null | xargs grep -l 'wp-admin\|wp-login' 2>/dev/null | head -1)
if [ -z "$VHOST" ]; then
    echo "FAIL [PoC]: No access restriction found for wp-admin/wp-login."; exit 1
fi
echo "PASS [PoC]: Access restrictions found for admin endpoints."

# Behavioral test: wp-admin must not be freely accessible (expect 403 or redirect)
if pgrep -x apache2 > /dev/null 2>&1 || pgrep -x httpd > /dev/null 2>&1; then
    ADMIN_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost/wp-admin/" 2>/dev/null)
    if [ "$ADMIN_CODE" = "200" ]; then
        echo "FAIL [PoC]: /wp-admin/ returned 200 — admin area not restricted."
        exit 1
    fi
    echo "PASS [PoC]: /wp-admin/ returned HTTP $ADMIN_CODE (access restricted)."

    LOGIN_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost/wp-login.php" 2>/dev/null)
    if [ "$LOGIN_CODE" = "200" ]; then
        echo "FAIL [PoC]: /wp-login.php returned 200 — login page not restricted."
        exit 1
    fi
    echo "PASS [PoC]: /wp-login.php returned HTTP $LOGIN_CODE (access restricted)."
fi

if pgrep -x apache2 > /dev/null 2>&1 || pgrep -x httpd > /dev/null 2>&1; then
    echo "PASS [Regression]: Web server running."
else echo "FAIL [Regression]: Web server not running."; exit 1; fi
echo "All checks passed."; exit 0
