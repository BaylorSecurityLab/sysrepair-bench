#!/bin/bash
# Verification script for Scenario 09: jQuery < 1.9.0 XSS (CVE-2012-6708)
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
#
# The authoritative check is DYNAMIC: it fetches the jQuery that Apache actually
# serves from Drupal's misc/ path and reads its version. A file swap that is not
# actually served (wrong path/perms) will not pass. The verifier never starts
# Apache; if it is down the fetch fails and the check fails, as intended.

PASS=true
URL="http://localhost/drupal/misc/jquery.js"

SERVED=$(timeout 20 curl -s "$URL")
if [ -z "$SERVED" ]; then
    echo "FAIL [Regression]: could not fetch $URL (Apache down or file missing)." >&2
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi

VER=$(printf '%s\n' "$SERVED" | head -20 | grep -oiE 'jQuery (JavaScript Library )?v[0-9]+\.[0-9]+\.[0-9]+' | head -1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+')
if [ -z "$VER" ]; then
    VER=$(printf '%s\n' "$SERVED" | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
fi
if [ -z "$VER" ]; then
    echo "FAIL [PoC]: could not determine the served jQuery version." >&2
    PASS=false
else
    echo "INFO: served jQuery $VER"
    MAJOR=$(echo "$VER" | sed -E 's/^v([0-9]+).*/\1/')
    MINOR=$(echo "$VER" | sed -E 's/^v[0-9]+\.([0-9]+).*/\1/')
    if [ "$MAJOR" -lt 1 ] || { [ "$MAJOR" -eq 1 ] && [ "$MINOR" -lt 9 ]; }; then
        echo "FAIL [PoC]: served jQuery $VER is < 1.9.0 -- vulnerable to CVE-2012-6708." >&2
        PASS=false
    else
        echo "PASS [PoC]: served jQuery $VER is >= 1.9.0 -- CVE-2012-6708 mitigated."
    fi
fi

# --- Regression: Drupal homepage must still return 200 ---
HOME_CODE=$(timeout 20 curl -so /dev/null -w '%{http_code}' http://localhost/drupal/)
if [ "$HOME_CODE" = "200" ]; then
    echo "PASS [Regression]: /drupal/ homepage is reachable (HTTP 200)."
else
    echo "FAIL [Regression]: /drupal/ returned HTTP $HOME_CODE -- expected 200." >&2
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
