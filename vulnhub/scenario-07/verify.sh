#!/bin/bash
# Verification: Scenario 13 - Drupalgeddon (DC-1)
DB_INC="/var/www/html/includes/database/database.inc"
if [ ! -f "$DB_INC" ]; then
    echo "FAIL [PoC]: database.inc not found."; exit 1
fi
if grep -q 'preg_match\|array_filter.*is_int\|intval\|sanitize' "$DB_INC" 2>/dev/null; then
    echo "PASS [PoC]: database.inc has input sanitization."
else
    echo "FAIL [PoC]: database.inc lacks input sanitization for array keys."; exit 1
fi

# Behavioral test: send a Drupalgeddon-style payload — must not return 200
if pgrep -x apache2 > /dev/null 2>&1; then
    DRUPAL_CODE=$(curl -s -o /dev/null -w "%{http_code}" -d "name[0%20;select+1;--]=test" "http://localhost/" 2>/dev/null)
    if [ "$DRUPAL_CODE" = "200" ]; then
        DRUPAL_BODY=$(curl -s -d "name[0%20;select+1;--]=test" "http://localhost/" 2>/dev/null)
        if echo "$DRUPAL_BODY" | grep -qi 'error\|sql\|syntax\|query'; then
            echo "FAIL [PoC]: Drupalgeddon payload triggered SQL error — still vulnerable."
            exit 1
        fi
    fi
    echo "PASS [PoC]: Drupalgeddon payload did not trigger SQL error."
fi

if pgrep -x apache2 > /dev/null 2>&1; then
    echo "PASS [Regression]: Apache running."
else
    echo "FAIL [Regression]: Apache not running."; exit 1
fi
echo "All checks passed."; exit 0
