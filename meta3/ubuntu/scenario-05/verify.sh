#!/bin/bash
# Verification script for Scenario 05: Unprotected Installer Pages
# Exit 0 = every check passed, Exit 1 = at least one check failed
#
# Fully dynamic: it drives the live Apache with real HTTP requests. It never
# starts the web server (it is booted by the image CMD); if Apache is down the
# homepage regression checks fail, which is the correct outcome.
#
# Two-component protocol: every check runs and is recorded with its kind, so
# "blocked the installers by killing Apache" reports security_pass=true /
# regression_pass=false instead of collapsing into a bare exit 1.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

code() { timeout 20 curl -so /dev/null -w '%{http_code}' "http://localhost/$1" || true; }

# --- PoC: installer/setup endpoints must be blocked (403, files still present) ---
#
# Only a real 403 counts. Anything else -- including curl's 000 "no response" --
# keeps the original strictness and fails: a request that was never answered is
# not evidence that a deny rule was deployed. Service death is caught by the
# regression checks below, which is where it belongs.
for path in drupal/install.php phpmyadmin/setup/index.php; do
    id="$(echo "$path" | tr '/.' '__')"
    c=$(code "$path")
    if [ "$c" = "403" ]; then
        record_poc "blocked_$id" 1
    else
        record_poc "blocked_$id" 0 "/$path returned HTTP $c -- expected 403"
    fi
done

# --- Regression: the applications themselves must remain reachable ---
for path in drupal/ phpmyadmin/; do
    id="$(echo "$path" | tr -d '/')"
    c=$(code "$path")
    if [ "$c" = "200" ]; then
        record_reg "app_reachable_$id" 1
    else
        record_reg "app_reachable_$id" 0 "/$path returned HTTP $c -- expected 200"
    fi
done

verify_finish
