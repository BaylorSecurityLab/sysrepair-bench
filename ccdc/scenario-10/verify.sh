#!/bin/bash
###############################################################################
# Scenario 10 - Verification Script
# Nginx autoindex on (directory listing)
#
# PoC checks:        autoindex is off in the config AND /files/ returns no
#                    listing on the wire
# Regression checks: nginx is running, serving the main page, config parses
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
# Exit 42 = precondition does not hold on this host
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "closed the vulnerability but killed nginx" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.
###############################################################################

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# --- PoC check: autoindex should be off ---
# WAS BROKEN TWO WAYS:
#  (a) FALSE NEGATIVE: `grep -r ... | grep -qi 'on'` matched the FILE PATH that
#      grep -r prefixes to every hit — "/etc/nginx/conf.d/default.c(on)f"
#      contains "on" — so the textbook-correct `autoindex off;` was reported as
#      "still enabled" and only DELETING the directive could pass.
#  (b) DEAD AT BASELINE: the shipped conf is a single line starting with
#      `server {`, so the anchored `^\s*autoindex` never matched and this check
#      PASSED on the vulnerable image.
# Now: strip comments, extract the directive VALUE (not the path), and handle
# the directive appearing inline inside a one-line server block.
AUTOINDEX_VALUES=$(grep -rh 'autoindex' /etc/nginx/ 2>/dev/null \
    | sed 's/#.*//' \
    | grep -oiE 'autoindex[[:space:]]+[A-Za-z]+' \
    | awk '{print tolower($2)}')

if echo "$AUTOINDEX_VALUES" | grep -qx 'on'; then
    record_poc autoindex_off_in_config 0 "autoindex is still enabled (directive value: on)"
elif [ -z "$AUTOINDEX_VALUES" ]; then
    record_poc autoindex_off_in_config 1 "autoindex directive is not set (nginx default is off)"
else
    record_poc autoindex_off_in_config 1 "autoindex is explicitly disabled (directive value(s): $(echo $AUTOINDEX_VALUES | tr '\n' ' '))"
fi

# --- Regression check: nginx must still be running ---
#
# The image CMD boots nginx with `autoindex on` (see .preserve-cmd), so a server
# is ALWAYS expected here. verify.sh must NEVER start or reload it: a freshly
# started nginx would pick up the agent's edited config and mask the "edited the
# config but never restarted" mistake. A dead server is recorded as the
# regression failure it is, and the live probe below then stays unmeasured
# rather than being scored as if it had run.
NGINX_UP=0
if pgrep -x nginx > /dev/null 2>&1; then
    NGINX_UP=1
    record_reg nginx_running 1
else
    record_reg nginx_running 0 "nginx is not running"
fi

# --- PoC behavioural check (RUNTIME, MANDATORY): request the listing ---
if [ "$NGINX_UP" -eq 0 ]; then
    echo "  [SKIP] nginx is not running - the live listing probe cannot be measured"
else
    LISTING=$(curl -s http://localhost/files/ 2>/dev/null)
    LISTING_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://localhost/files/ 2>/dev/null)
    if [ -z "$LISTING_CODE" ] || [ "$LISTING_CODE" = "000" ]; then
        # No HTTP response at all is a broken service, not proof listing is off.
        record_reg http_response_received 0 "no HTTP response for /files/ - cannot prove listing is off"
    elif echo "$LISTING" | grep -qi "Index of /files"; then
        record_reg http_response_received 1
        record_poc dir_listing_refused 0 \
            "directory listing accessible via HTTP (config may say autoindex off, but nginx was never restarted)"
    else
        record_reg http_response_received 1
        record_poc dir_listing_refused 1
    fi
fi

# --- Regression check: Nginx should serve the main page ---
# Do NOT start nginx here - it is supposed to already be running, and starting
# it would hide a server the agent stopped or broke.
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/ 2>/dev/null)
if [[ "$RESPONSE" == "200" ]]; then
    record_reg nginx_serving_main_page 1
else
    record_reg nginx_serving_main_page 0 "Nginx is not serving the main page (HTTP $RESPONSE)"
fi

# --- Regression check: Nginx config syntax must still be valid ---
if nginx -t 2>&1 | grep -q "syntax is ok"; then
    record_reg nginx_config_valid 1
else
    record_reg nginx_config_valid 0 "Nginx configuration syntax is invalid"
fi

verify_finish
