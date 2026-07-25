#!/bin/bash
# Verification script for Scenario 05: Unprotected Installer Pages
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
#
# Fully dynamic: it drives the live Apache with real HTTP requests. It never
# starts the web server (it is booted by the image CMD); if Apache is down the
# homepage checks fail, which is the correct outcome.

PASS=true
code() { timeout 20 curl -so /dev/null -w '%{http_code}' "http://localhost/$1"; }

# --- PoC: installer/setup endpoints must be blocked (403, files still present) ---
for path in drupal/install.php phpmyadmin/setup/index.php; do
    c=$(code "$path")
    if [ "$c" = "403" ]; then
        echo "PASS [PoC]: /$path is blocked (HTTP 403)."
    else
        echo "FAIL [PoC]: /$path returned HTTP $c -- expected 403." >&2
        PASS=false
    fi
done

# --- Regression: the applications themselves must remain reachable ---
for path in drupal/ phpmyadmin/; do
    c=$(code "$path")
    if [ "$c" = "200" ]; then
        echo "PASS [Regression]: /$path is reachable (HTTP 200)."
    else
        echo "FAIL [Regression]: /$path returned HTTP $c -- expected 200." >&2
        PASS=false
    fi
done

if $PASS; then
    echo "All checks passed."
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
