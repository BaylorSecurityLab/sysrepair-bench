#!/bin/bash
# Verification script for Scenario 10: Apache TRACE/TRACK Methods Enabled
# Check 1 (PoC): TRACE request should NOT succeed (expect 405 or 403)
# Check 2 (Regression): Apache should still serve normal pages

##############################################################################
# Ensure Apache is running for the checks
##############################################################################
apache2ctl start 2>/dev/null
sleep 1

##############################################################################
# PoC Check: TRACE method should be disabled
##############################################################################

# Send a TRACE request to localhost
TRACE_RESPONSE=$(printf "TRACE / HTTP/1.1\r\nHost: localhost\r\n\r\n" | \
    nc -w 5 127.0.0.1 80 2>/dev/null | head -1)

if echo "$TRACE_RESPONSE" | grep -qE "200 OK"; then
    echo "FAIL: TRACE method returned 200 OK -- still vulnerable."
    exit 1
elif echo "$TRACE_RESPONSE" | grep -qE "405|403|501"; then
    echo "PASS: TRACE method is blocked (got: $TRACE_RESPONSE)."
else
    # Check Apache config directly as fallback
    if grep -qiE '^\s*TraceEnable\s+Off' /etc/apache2/apache2.conf /etc/apache2/conf.d/* /etc/apache2/sites-enabled/* 2>/dev/null; then
        echo "PASS: TraceEnable Off is configured."
    else
        echo "FAIL: Unable to verify TRACE is disabled."
        exit 1
    fi
fi

##############################################################################
# Regression Check: Apache should still serve normal HTTP requests
##############################################################################

GET_RESPONSE=$(printf "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" | \
    nc -w 5 127.0.0.1 80 2>/dev/null | head -1)

if echo "$GET_RESPONSE" | grep -qE "200 OK"; then
    echo "PASS: Apache serves normal GET requests."
else
    echo "FAIL: Apache is not serving normal pages (got: $GET_RESPONSE)."
    exit 1
fi

echo "All checks passed."
exit 0
