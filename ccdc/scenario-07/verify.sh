#!/bin/bash
###############################################################################
# Scenario 07 - Verification Script
# Apache directory listing enabled
#
# PoC checks:        directory listing is disabled, in the config AND on the wire
# Regression checks: apache2 is running and still serves the main page
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
# Exit 42 = precondition does not hold on this host
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "closed the vulnerability but killed apache2" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.
###############################################################################

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# --- PoC check: Directory listing should be disabled ---
# Check Apache config for Indexes option
if grep -rqE 'Options.*\bIndexes\b' /etc/apache2/apache2.conf /etc/apache2/sites-enabled/ /etc/apache2/conf-enabled/ 2>/dev/null | grep -v '\-Indexes'; then
    # More precise check: look for +Indexes or bare Indexes (not -Indexes)
    HAS_INDEXES=$(grep -rn 'Options' /etc/apache2/apache2.conf /etc/apache2/sites-enabled/ /etc/apache2/conf-enabled/ 2>/dev/null | grep -v '#' | grep 'Indexes' | grep -v '\-Indexes')
    if [ -n "$HAS_INDEXES" ]; then
        record_poc indexes_not_in_config 0 "directory listing (Indexes) is still enabled"
    else
        record_poc indexes_not_in_config 1
    fi
else
    record_poc indexes_not_in_config 1
fi

# --- Regression check: apache2 must still be running ---
#
# The image CMD boots apache2 with Indexes enabled (see .preserve-cmd), so a
# server is ALWAYS expected here. verify.sh must never start it: a freshly
# started httpd would load the agent's edited config and mask the not-restarted
# case. A dead server is recorded as the regression failure it is, and the live
# probe below then stays unmeasured rather than being scored as if it had run.
APACHE_UP=0
if pgrep -x apache2 > /dev/null 2>&1; then
    APACHE_UP=1
    record_reg apache2_running 1
else
    record_reg apache2_running 0 "apache2 is not running"
fi

# --- PoC behavioural check (RUNTIME, MANDATORY): actually request the listing ---
#
# The grep above only reads CONFIG FILES. Removing "Indexes" from a config and
# never restarting apache2 leaves the running server happily enumerating
# /data/ for any anonymous client - that state must FAIL. So fetch the
# directory over HTTP and look at what the LIVE server returns.
if [ "$APACHE_UP" -eq 0 ]; then
    echo "  [SKIP] apache2 is not running - the live listing probe cannot be measured"
else
    LISTING=$(curl -s --max-time 10 http://localhost/data/ 2>/dev/null)
    LISTING_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://localhost/data/ 2>/dev/null)
    if [ -z "$LISTING_CODE" ] || [ "$LISTING_CODE" = "000" ]; then
        # No HTTP response at all is a broken service, not proof the listing is
        # off, so it is recorded as a regression failure.
        record_reg http_response_received 0 "no HTTP response for /data/ - cannot prove listing is off"
    elif echo "$LISTING" | grep -qi "Index of /data"; then
        record_reg http_response_received 1
        record_poc dir_listing_refused 0 \
            "directory listing is accessible via HTTP (HTTP $LISTING_CODE; config may look clean, but apache2 was never restarted)"
    elif echo "$LISTING" | grep -qiE '<a href="[^"]+">[^<]*</a>.*[0-9]{4}-[0-9]{2}-[0-9]{2}'; then
        # mod_autoindex with a custom HeaderName still emits a file table.
        record_reg http_response_received 1
        record_poc dir_listing_refused 0 "/data/ still returns an autoindex file listing (HTTP $LISTING_CODE)"
    else
        record_reg http_response_received 1
        record_poc dir_listing_refused 1 "directory listing not accessible via HTTP (HTTP $LISTING_CODE)"
    fi
fi

# --- Regression check: Apache should serve the main page ---
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/ 2>/dev/null)
if [[ "$RESPONSE" == "200" ]]; then
    record_reg apache_serving_main_page 1
else
    record_reg apache_serving_main_page 0 "Apache is not serving the main page (HTTP $RESPONSE)"
fi

verify_finish
