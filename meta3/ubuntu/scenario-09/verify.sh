#!/bin/bash
# Verification script for Scenario 09: jQuery < 1.9.0 XSS (CVE-2012-6708)
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

JQUERY_FILE="/var/www/html/drupal/misc/jquery.js"

###############################################################################
# PoC Check: jquery.js must NOT contain a version < 1.9
###############################################################################

if [ ! -f "$JQUERY_FILE" ]; then
    echo "FAIL [PoC]: $JQUERY_FILE not found — Drupal may not be installed." >&2
    exit 1
fi

# Extract the version string from the first 5 lines (jQuery header comment)
VERSION_LINE=$(head -5 "$JQUERY_FILE" | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
if [ -z "$VERSION_LINE" ]; then
    # Some minified builds embed the version differently
    VERSION_LINE=$(grep -oE 'jQuery v[0-9]+\.[0-9]+\.[0-9]+' "$JQUERY_FILE" | head -1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+')
fi

if [ -z "$VERSION_LINE" ]; then
    echo "FAIL [PoC]: Could not determine jQuery version from $JQUERY_FILE." >&2
    exit 1
fi

MAJOR=$(echo "$VERSION_LINE" | grep -oE '[0-9]+' | sed -n '1p')
MINOR=$(echo "$VERSION_LINE" | grep -oE '[0-9]+' | sed -n '2p')

echo "INFO: Detected jQuery $VERSION_LINE"

if [ "$MAJOR" -lt 1 ] || { [ "$MAJOR" -eq 1 ] && [ "$MINOR" -lt 9 ]; }; then
    echo "FAIL [PoC]: jQuery $VERSION_LINE is < 1.9.0 and vulnerable to CVE-2012-6708." >&2
    exit 1
fi
echo "PASS [PoC]: jQuery $VERSION_LINE is >= 1.9.0 — CVE-2012-6708 mitigated."

# Cross-check: verify the old version string pattern is gone
if curl -s http://localhost/drupal/misc/jquery.js | grep -qE 'v1\.[0-8]\.'; then
    echo "FAIL [PoC]: The served jquery.js still reports a version < 1.9.x." >&2
    exit 1
fi
echo "PASS [PoC]: Served jquery.js does not report a version < 1.9.x."

###############################################################################
# Regression Check: Drupal homepage must still return 200
###############################################################################

HOME_CODE=$(curl -so /dev/null -w '%{http_code}' http://localhost/drupal/)
if [ "$HOME_CODE" != "200" ]; then
    echo "FAIL [Regression]: /drupal/ returned HTTP $HOME_CODE — expected 200." >&2
    exit 1
fi
echo "PASS [Regression]: /drupal/ homepage is reachable (HTTP 200)."

echo "All checks passed."
exit 0
