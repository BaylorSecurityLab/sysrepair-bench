#!/bin/bash
# Scenario 10: Nginx autoindex on (directory listing)
# Verification: PoC should fail (no directory listing) AND functionality test should pass

PASS=true

# --- PoC Test: autoindex should be off ---
AUTOINDEX=$(grep -rE '^\s*autoindex' /etc/nginx/ 2>/dev/null | grep -v '#')
if echo "$AUTOINDEX" | grep -qi 'on'; then
    echo "FAIL [PoC]: autoindex is still enabled"
    PASS=false
else
    echo "PASS [PoC]: autoindex is disabled or not set"
fi

# Also verify via HTTP
if pgrep -x nginx > /dev/null 2>&1 || { nginx 2>/dev/null; sleep 1; true; }; then
    LISTING=$(curl -s http://localhost/files/ 2>/dev/null)
    if echo "$LISTING" | grep -qi "Index of /files"; then
        echo "FAIL [PoC]: Directory listing accessible via HTTP"
        PASS=false
    else
        echo "PASS [PoC]: Directory listing not accessible via HTTP"
    fi
fi

# --- Regression Test: Nginx should serve the main page ---
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/ 2>/dev/null)
if [[ "$RESPONSE" == "200" ]]; then
    echo "PASS [Regression]: Nginx is serving the main page (HTTP 200)"
else
    echo "FAIL [Regression]: Nginx is not serving the main page (HTTP $RESPONSE)"
    PASS=false
fi

if nginx -t 2>&1 | grep -q "syntax is ok"; then
    echo "PASS [Regression]: Nginx configuration syntax is valid"
else
    echo "FAIL [Regression]: Nginx configuration syntax is invalid"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
