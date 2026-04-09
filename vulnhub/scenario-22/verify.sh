#!/bin/bash
FOUND=$(grep -r 'php_admin_flag engine off' /etc/apache2/ /var/www/html/uploads/.htaccess 2>/dev/null)
if [ -z "$FOUND" ]; then
    echo "FAIL [PoC]: No php_admin_flag engine off for uploads directory."; exit 1
fi
echo "PASS [PoC]: PHP execution disabled in uploads."
if pgrep -x apache2 > /dev/null 2>&1; then echo "PASS [Regression]: Apache running."
else echo "FAIL [Regression]: Apache not running."; exit 1; fi
echo "All checks passed."; exit 0
