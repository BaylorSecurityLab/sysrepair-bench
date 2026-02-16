#!/bin/bash
# Verification script for Scenario 11: Apache Dangerous HTTP Methods (PUT/DELETE via WebDAV)
# Check 1 (PoC): PUT upload to /dav/ should NOT succeed without auth
# Check 2 (Regression): Apache should still serve normal pages

##############################################################################
# Ensure Apache is running for the checks
##############################################################################
apache2ctl start 2>/dev/null
sleep 1

##############################################################################
# PoC Check: Attempt to PUT a file to /dav/ -- should fail
##############################################################################

PUT_RESPONSE=$(printf "PUT /dav/testfile.txt HTTP/1.1\r\nHost: localhost\r\nContent-Length: 11\r\n\r\nHELLO WORLD" | \
    nc -w 5 127.0.0.1 80 2>/dev/null | head -1)

if echo "$PUT_RESPONSE" | grep -qE "201 Created|200 OK|204 No Content"; then
    echo "FAIL: PUT upload succeeded without authentication -- still vulnerable."
    # Clean up uploaded file
    rm -f /var/www/dav/testfile.txt 2>/dev/null
    exit 1
elif echo "$PUT_RESPONSE" | grep -qE "401|403|405|501"; then
    echo "PASS: PUT upload was rejected (got: $PUT_RESPONSE)."
else
    # If WebDAV module is disabled entirely, PUT will likely get 405
    # Also check if mod_dav is still loaded
    if apache2ctl -M 2>/dev/null | grep -q 'dav_module'; then
        # mod_dav is loaded -- check if /dav/ requires auth
        if grep -rqE 'AuthType|Require valid-user' /etc/apache2/sites-enabled/ 2>/dev/null; then
            echo "PASS: WebDAV directory has authentication configured."
        else
            echo "FAIL: mod_dav is loaded and /dav/ may still be open."
            exit 1
        fi
    else
        echo "PASS: mod_dav is disabled."
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
