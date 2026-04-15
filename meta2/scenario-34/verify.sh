#!/bin/bash
# Scenario 34: PHP-CGI CVE-2012-1823 — compensating control (mod_rewrite guard)
# PoC  : GET /cgi-bin/legacy.php?-s must NOT return PHP source (must be 403)
# Reg. : GET /cgi-bin/legacy.php must still return LEGACY_APP_OK

set -u

if ! pgrep -f apache2 > /dev/null 2>&1; then
    apache2ctl start > /dev/null 2>&1
    sleep 1
fi

EXPLOIT_STATUS=$(curl -s -o /dev/null -w '%{http_code}' 'http://127.0.0.1/cgi-bin/legacy.php?-s')
if [ "$EXPLOIT_STATUS" != "403" ] && [ "$EXPLOIT_STATUS" != "404" ]; then
    EXPLOIT_BODY=$(curl -s 'http://127.0.0.1/cgi-bin/legacy.php?-s')
    if echo "$EXPLOIT_BODY" | grep -qi '<?php\|LEGACY_APP_OK'; then
        echo "FAIL [PoC]: php-cgi still interprets ?-s (source disclosure). status=$EXPLOIT_STATUS"
        exit 1
    fi
fi
echo "PASS [PoC]: dash-prefixed query string blocked (status=$EXPLOIT_STATUS)."

LEGIT_BODY=$(curl -s 'http://127.0.0.1/cgi-bin/legacy.php')
if ! echo "$LEGIT_BODY" | grep -q 'LEGACY_APP_OK'; then
    echo "FAIL [Regression]: legacy PHP-CGI app no longer reachable. body=$LEGIT_BODY"
    exit 1
fi
echo "PASS [Regression]: legacy PHP-CGI app still functional."

echo "All checks passed."
exit 0
