#!/bin/bash
# Scenario 07: Apache directory listing enabled
# Verification: PoC should fail (no dir listing) AND functionality test should pass

PASS=true

# --- PoC Test: Directory listing should be disabled ---
# Check Apache config for Indexes option
if grep -rqE 'Options.*\bIndexes\b' /etc/apache2/apache2.conf /etc/apache2/sites-enabled/ /etc/apache2/conf-enabled/ 2>/dev/null | grep -v '\-Indexes'; then
    # More precise check: look for +Indexes or bare Indexes (not -Indexes)
    HAS_INDEXES=$(grep -rn 'Options' /etc/apache2/apache2.conf /etc/apache2/sites-enabled/ /etc/apache2/conf-enabled/ 2>/dev/null | grep -v '#' | grep 'Indexes' | grep -v '\-Indexes')
    if [ -n "$HAS_INDEXES" ]; then
        echo "FAIL [PoC]: Directory listing (Indexes) is still enabled"
        PASS=false
    else
        echo "PASS [PoC]: Directory listing is disabled"
    fi
else
    echo "PASS [PoC]: Directory listing is disabled"
fi

# Also verify by HTTP if Apache is running
if pgrep -x apache2 > /dev/null 2>&1 || { apachectl start 2>/dev/null; sleep 1; pgrep -x apache2 > /dev/null 2>&1; }; then
    LISTING=$(curl -s http://localhost/data/ 2>/dev/null)
    if echo "$LISTING" | grep -qi "Index of /data"; then
        echo "FAIL [PoC]: Directory listing is accessible via HTTP"
        PASS=false
    else
        echo "PASS [PoC]: Directory listing not accessible via HTTP"
    fi
fi

# --- Regression Test: Apache should serve the main page ---
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/ 2>/dev/null)
if [[ "$RESPONSE" == "200" ]]; then
    echo "PASS [Regression]: Apache is serving the main page (HTTP 200)"
else
    echo "FAIL [Regression]: Apache is not serving the main page (HTTP $RESPONSE)"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
