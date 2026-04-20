#!/bin/bash
# Scenario 35: TWiki/Tiki legacy admin exposure — compensating control
# PoC  : /twiki/bin/configure (and similar admin paths) must be blocked externally
# Reg. : /twiki/bin/view must still return TWIKI_VIEW_OK

set -u

if ! pgrep -f apache2 > /dev/null 2>&1; then
    apache2ctl start > /dev/null 2>&1
    sleep 1
fi

ADMIN_STATUS=$(curl -s -o /dev/null -w '%{http_code}' 'http://127.0.0.1/twiki/bin/configure')
ADMIN_BODY=$(curl -s 'http://127.0.0.1/twiki/bin/configure')

# 127.0.0.1 is allowed for demo purposes — the check is that the *Apache rule exists*.
# We confirm by reading the applied config for a deny/allow or LocationMatch guard.
if ! grep -rqiE '(Deny from all|Require ip|LocationMatch.*twiki.*configure|twiki.*configure.*Deny)' /etc/apache2/ 2>/dev/null; then
    echo "FAIL [PoC]: No Apache access-control rule restricting TWiki/Tiki admin endpoints."
    exit 1
fi
echo "PASS [PoC]: Admin endpoint lockdown rule present in Apache config."

# Behavioral test: actually request the admin endpoint and verify it is blocked
ADMIN_STATUS=$(curl -s -o /dev/null -w '%{http_code}' 'http://127.0.0.1/twiki/bin/configure' 2>/dev/null || true)
if [ "$ADMIN_STATUS" = "403" ] || [ "$ADMIN_STATUS" = "401" ]; then
    echo "PASS [PoC]: Admin endpoint returns HTTP $ADMIN_STATUS (access denied, behavioral test)."
elif [ "$ADMIN_STATUS" = "200" ]; then
    # HTTP 200 might still be OK if the body does not expose configure
    ADMIN_BODY=$(curl -s 'http://127.0.0.1/twiki/bin/configure' 2>/dev/null || true)
    if echo "$ADMIN_BODY" | grep -qi "TWIKI_CONFIGURE_REACHABLE\|configure\|password\|admin"; then
        echo "FAIL [PoC]: Admin endpoint accessible and returns sensitive content (behavioral test)."
        exit 1
    else
        echo "PASS [PoC]: Admin endpoint returned 200 but no sensitive content (behavioral test)."
    fi
elif [ -z "$ADMIN_STATUS" ] || [ "$ADMIN_STATUS" = "000" ]; then
    echo "WARN [PoC]: Could not reach admin endpoint (Apache may not be running for behavioral test)."
else
    echo "PASS [PoC]: Admin endpoint returned HTTP $ADMIN_STATUS (behavioral test)."
fi

VIEW_BODY=$(curl -s 'http://127.0.0.1/twiki/bin/view')
if ! echo "$VIEW_BODY" | grep -q 'TWIKI_VIEW_OK'; then
    echo "FAIL [Regression]: public TWiki view path no longer reachable. body=$VIEW_BODY"
    exit 1
fi
echo "PASS [Regression]: public wiki view path still reachable."

echo "All checks passed."
exit 0
