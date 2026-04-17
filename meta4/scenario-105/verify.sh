#!/bin/bash
# Scenario 105: Next.js Middleware Auth Bypass (CVE-2025-29927)
set -u

###############################################################################
# PoC: x-middleware-subrequest header must NOT bypass middleware auth
# After remediation nginx strips the header; /protected must return 401.
###############################################################################

STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H 'x-middleware-subrequest: middleware' \
    http://localhost/protected)

if [ "$STATUS" = "200" ]; then
    echo "FAIL [PoC]: /protected returned 200 with x-middleware-subrequest header — bypass still works." >&2
    exit 1
fi
echo "PASS [PoC]: /protected returned $STATUS (not 200) with bypass header — header is stripped."

###############################################################################
# Regression: public page must still be reachable via nginx on port 80
###############################################################################

STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/)
if [ "$STATUS" != "200" ]; then
    echo "FAIL [Regression]: / returned $STATUS via nginx — proxy not working." >&2
    exit 1
fi
echo "PASS [Regression]: / returns 200 via nginx on port 80."

exit 0
