#!/bin/bash
PLUGIN_DIR="/var/www/html/wp-content/plugins"
PERMS=$(stat -c %a "$PLUGIN_DIR" 2>/dev/null)
if [ "$PERMS" = "777" ]; then
    echo "FAIL [PoC]: Plugin directory still 777."; exit 1
fi
echo "PASS [PoC]: Plugin directory permissions: $PERMS"
if pgrep -x apache2 > /dev/null 2>&1; then echo "PASS [Regression]: Apache running."
else echo "FAIL [Regression]: Apache not running."; exit 1; fi
echo "All checks passed."; exit 0
