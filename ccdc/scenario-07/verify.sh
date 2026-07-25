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

# --- PoC Behavioral Test (RUNTIME, MANDATORY): actually request the listing ---
#
# The grep above only reads CONFIG FILES. Removing "Indexes" from a config and
# never restarting apache2 leaves the running server happily enumerating
# /data/ for any anonymous client - that state must FAIL. So fetch the
# directory over HTTP and look at what the LIVE server returns.
#
# The image CMD boots apache2 with Indexes enabled (see .preserve-cmd), so a
# server is ALWAYS expected here. verify.sh must never start it: a freshly
# started httpd would load the agent's edited config and mask the not-restarted
# case. A dead server is a failure.
if ! pgrep -x apache2 > /dev/null 2>&1; then
    echo "FAIL [PoC]: apache2 is not running - cannot prove directory listing is off"
    PASS=false
else
    LISTING=$(curl -s --max-time 10 http://localhost/data/ 2>/dev/null)
    LISTING_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://localhost/data/ 2>/dev/null)
    if [ -z "$LISTING_CODE" ] || [ "$LISTING_CODE" = "000" ]; then
        echo "FAIL [PoC]: no HTTP response for /data/ - cannot prove listing is off"
        PASS=false
    elif echo "$LISTING" | grep -qi "Index of /data"; then
        echo "FAIL [PoC]: Directory listing is accessible via HTTP (HTTP $LISTING_CODE)"
        echo "            (config may look clean, but apache2 was never restarted)"
        PASS=false
    elif echo "$LISTING" | grep -qiE '<a href="[^"]+">[^<]*</a>.*[0-9]{4}-[0-9]{2}-[0-9]{2}'; then
        # mod_autoindex with a custom HeaderName still emits a file table.
        echo "FAIL [PoC]: /data/ still returns an autoindex file listing (HTTP $LISTING_CODE)"
        PASS=false
    else
        echo "PASS [PoC]: Directory listing not accessible via HTTP (HTTP $LISTING_CODE)"
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
