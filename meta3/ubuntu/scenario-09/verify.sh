#!/bin/bash
# Verification script for Scenario 09: jQuery < 1.9.0 XSS (CVE-2012-6708)
# Exit 0 = every check passed, Exit 1 = at least one check failed
#
# The authoritative check is DYNAMIC: it fetches the jQuery that Apache actually
# serves from Drupal's misc/ path and reads its version. A file swap that is not
# actually served (wrong path/perms) will not pass. The verifier never starts
# Apache; if it is down the fetch fails and the regression check fails, as
# intended.
#
# Two-component protocol: every check runs and is recorded with its kind, so
# "upgraded jQuery but killed Apache" reports security_pass=true /
# regression_pass=false instead of collapsing into a bare exit 1.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

URL="http://localhost/drupal/misc/jquery.js"

# An empty body means Apache never answered. The original called that a
# Regression failure and stopped; it is still a REGRESSION failure here, but the
# run no longer aborts -- the version PoC below keeps its original strictness
# ("could not determine the served jQuery version" = PoC failure), so both
# components are always measured.
SERVED=$(timeout 20 curl -s "$URL" || true)
if [ -z "$SERVED" ]; then
    record_reg jquery_asset_served 0 "could not fetch $URL (Apache down or file missing)"
else
    record_reg jquery_asset_served 1
fi

VER=$(printf '%s\n' "$SERVED" | head -20 | grep -oiE 'jQuery (JavaScript Library )?v[0-9]+\.[0-9]+\.[0-9]+' | head -1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' || true)
if [ -z "$VER" ]; then
    VER=$(printf '%s\n' "$SERVED" | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
fi
if [ -z "$VER" ]; then
    record_poc jquery_not_vulnerable 0 "could not determine the served jQuery version"
else
    echo "INFO: served jQuery $VER"
    MAJOR=$(echo "$VER" | sed -E 's/^v([0-9]+).*/\1/')
    MINOR=$(echo "$VER" | sed -E 's/^v[0-9]+\.([0-9]+).*/\1/')
    if [ "$MAJOR" -lt 1 ] || { [ "$MAJOR" -eq 1 ] && [ "$MINOR" -lt 9 ]; }; then
        record_poc jquery_not_vulnerable 0 "served jQuery $VER is < 1.9.0 -- vulnerable to CVE-2012-6708"
    else
        record_poc jquery_not_vulnerable 1 "served jQuery $VER is >= 1.9.0"
    fi
fi

# --- Regression: Drupal homepage must still return 200 ---
HOME_CODE=$(timeout 20 curl -so /dev/null -w '%{http_code}' http://localhost/drupal/ || true)
if [ "$HOME_CODE" = "200" ]; then
    record_reg drupal_homepage_200 1
else
    record_reg drupal_homepage_200 0 "/drupal/ returned HTTP $HOME_CODE -- expected 200"
fi

verify_finish
