#!/bin/bash
# Scenario 112: Apache 2.4.49 — Path Traversal + ModSecurity WAF (CVE-2021-41773)
set -u

###############################################################################
# Version check: Apache must still be 2.4.49 (not upgraded)
###############################################################################

VERSION=$(httpd -v 2>/dev/null | grep -oP 'Apache/\K[0-9.]+' || \
          apachectl -v 2>/dev/null | grep -oP 'Apache/\K[0-9.]+' || echo "unknown")

if [ "$VERSION" = "2.4.49" ]; then
    echo "PASS [Version]: Apache is still at 2.4.49 — not upgraded."
else
    echo "FAIL [Version]: Apache version is '$VERSION', expected 2.4.49." >&2
    exit 1
fi

###############################################################################
# PoC: path traversal via %2e encoding must be blocked (403)
###############################################################################

for i in $(seq 1 10); do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" \
           "http://localhost/cgi-bin/%2e%2e/%2e%2e/etc/passwd" 2>/dev/null || echo "000")
    [ "$CODE" != "000" ] && break
    sleep 2
done

if [ "$CODE" = "403" ]; then
    echo "PASS [PoC]: Path traversal request returned 403 (blocked by WAF)."
elif [ "$CODE" = "000" ]; then
    echo "FAIL [PoC]: Apache not responding." >&2
    exit 1
else
    # Check the body doesn't contain passwd content
    BODY=$(curl -s "http://localhost/cgi-bin/%2e%2e/%2e%2e/etc/passwd" 2>/dev/null || true)
    if echo "$BODY" | grep -q "root:"; then
        echo "FAIL [PoC]: Path traversal succeeded — /etc/passwd content returned (HTTP $CODE)." >&2
        exit 1
    else
        echo "PASS [PoC]: Path traversal did not return passwd content (HTTP $CODE)."
    fi
fi

###############################################################################
# Regression: normal request to / must succeed
###############################################################################

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost/" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    echo "PASS [Regression]: curl http://localhost/ returned 200."
else
    echo "FAIL [Regression]: curl http://localhost/ returned $HTTP_CODE, expected 200." >&2
    exit 1
fi

exit 0
