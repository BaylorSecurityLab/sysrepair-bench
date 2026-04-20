#!/bin/bash
PLUGIN_DIR="/var/www/html/wp-content/plugins"
PERMS=$(stat -c %a "$PLUGIN_DIR" 2>/dev/null)
if [ "$PERMS" = "777" ]; then
    echo "FAIL [PoC]: Plugin directory still 777."; exit 1
fi
echo "PASS [PoC]: Plugin directory permissions: $PERMS"

# Behavioral test: attempt to upload a file via PUT — must fail
if pgrep -x apache2 > /dev/null 2>&1; then
    UPLOAD_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "http://localhost/wp-content/plugins/test-upload.php" -d "<?php echo 1; ?>" 2>/dev/null)
    if [ "$UPLOAD_CODE" = "200" ] || [ "$UPLOAD_CODE" = "201" ]; then
        echo "FAIL [PoC]: File upload via PUT returned $UPLOAD_CODE — upload not blocked."
        exit 1
    fi
    echo "PASS [PoC]: File upload via PUT blocked (HTTP $UPLOAD_CODE)."

    # Also verify we cannot write to the plugin directory as www-data
    if su -s /bin/sh www-data -c "touch /var/www/html/wp-content/plugins/evil.php" 2>/dev/null; then
        rm -f /var/www/html/wp-content/plugins/evil.php
        echo "FAIL [PoC]: www-data can write to plugins directory."
        exit 1
    fi
    echo "PASS [PoC]: www-data cannot write to plugins directory."
fi

if pgrep -x apache2 > /dev/null 2>&1; then echo "PASS [Regression]: Apache running."
else echo "FAIL [Regression]: Apache not running."; exit 1; fi
echo "All checks passed."; exit 0
