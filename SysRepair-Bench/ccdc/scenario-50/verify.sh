#!/bin/bash
# Scenario 50: World-writable web document root
# Verification: PoC should fail (not world-writable) AND functionality test should pass

PASS=true

# --- PoC Test: /var/www/html should not be world-writable ---
PERMS=$(stat -c "%a" /var/www/html 2>/dev/null)
OTHERS_PERM=${PERMS: -1}

if [[ "$OTHERS_PERM" == "7" ]] || [[ "$OTHERS_PERM" == "6" ]] || [[ "$OTHERS_PERM" == "3" ]] || [[ "$OTHERS_PERM" == "2" ]]; then
    echo "FAIL [PoC]: /var/www/html is world-writable (permissions: $PERMS)"
    PASS=false
else
    echo "PASS [PoC]: /var/www/html is not world-writable (permissions: $PERMS)"
fi

# Check files inside are not world-writable
WW_FILES=$(find /var/www/html -type f -perm -o+w 2>/dev/null | head -5)
if [ -n "$WW_FILES" ]; then
    echo "FAIL [PoC]: World-writable files found in /var/www/html"
    PASS=false
else
    echo "PASS [PoC]: No world-writable files in /var/www/html"
fi

# Check ownership
OWNER=$(stat -c "%U:%G" /var/www/html 2>/dev/null)
if [[ "$OWNER" == "www-data:www-data" ]] || [[ "$OWNER" == "root:root" ]] || [[ "$OWNER" == "root:www-data" ]]; then
    echo "PASS [PoC]: /var/www/html ownership is correct ($OWNER)"
else
    echo "FAIL [PoC]: /var/www/html has unexpected ownership ($OWNER)"
    PASS=false
fi

# --- Regression Test: Nginx should serve the website ---
if ! pgrep -x nginx > /dev/null 2>&1; then
    nginx 2>/dev/null
    sleep 1
fi

RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/ 2>/dev/null)
if [[ "$RESPONSE" == "200" ]]; then
    echo "PASS [Regression]: Nginx is serving the website (HTTP 200)"
else
    echo "FAIL [Regression]: Nginx is not serving the website (HTTP $RESPONSE)"
    PASS=false
fi

# Check content is intact
CONTENT=$(curl -s http://localhost/ 2>/dev/null)
if echo "$CONTENT" | grep -q "Company Website"; then
    echo "PASS [Regression]: Website content is intact"
else
    echo "FAIL [Regression]: Website content is missing or corrupted"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
