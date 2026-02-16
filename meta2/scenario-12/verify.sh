#!/bin/bash
# Verification script for Scenario 12: Apache /doc Directory Browsable
# Check 1 (PoC): /doc/ should NOT return a directory listing (expect 403 or 404)
# Check 2 (Regression): Apache should still serve normal pages

##############################################################################
# Ensure Apache is running for the checks
##############################################################################
apache2ctl start 2>/dev/null
sleep 1

##############################################################################
# PoC Check: /doc/ should not be browsable
##############################################################################

DOC_RESPONSE=$(printf "GET /doc/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" | \
    nc -w 5 127.0.0.1 80 2>/dev/null)

DOC_STATUS=$(echo "$DOC_RESPONSE" | head -1)

if echo "$DOC_STATUS" | grep -qE "200 OK"; then
    # Got 200 -- check if it contains a directory index
    if echo "$DOC_RESPONSE" | grep -qi "Index of /doc"; then
        echo "FAIL: /doc/ returns a browsable directory listing -- still vulnerable."
        exit 1
    else
        echo "PASS: /doc/ returns 200 but no directory index."
    fi
elif echo "$DOC_STATUS" | grep -qE "403|404|301"; then
    echo "PASS: /doc/ access is denied or not found (got: $DOC_STATUS)."
else
    # If Apache is not responding on /doc at all, check config
    if [ ! -f /etc/apache2/conf.d/doc ] && ! grep -rq 'Alias /doc' /etc/apache2/ 2>/dev/null; then
        echo "PASS: /doc alias has been removed from Apache config."
    elif grep -rqE 'Deny from all' /etc/apache2/conf.d/doc 2>/dev/null; then
        echo "PASS: /doc directory is denied in Apache config."
    else
        echo "FAIL: Unable to confirm /doc/ is protected."
        exit 1
    fi
fi

##############################################################################
# Regression Check: Apache should still serve the main site
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
