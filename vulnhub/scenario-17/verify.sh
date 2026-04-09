#!/bin/bash
VHOST=$(find /etc/apache2 /etc/httpd -name "*.conf" 2>/dev/null | xargs grep -l 'wp-admin\|wp-login' 2>/dev/null | head -1)
if [ -z "$VHOST" ]; then
    echo "FAIL [PoC]: No access restriction found for wp-admin/wp-login."; exit 1
fi
echo "PASS [PoC]: Access restrictions found for admin endpoints."
if pgrep -x apache2 > /dev/null 2>&1 || pgrep -x httpd > /dev/null 2>&1; then
    echo "PASS [Regression]: Web server running."
else echo "FAIL [Regression]: Web server not running."; exit 1; fi
echo "All checks passed."; exit 0
