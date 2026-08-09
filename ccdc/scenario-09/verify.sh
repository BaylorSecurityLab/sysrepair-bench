#!/bin/bash
###############################################################################
# Scenario 09 - Verification Script
# Nginx server_tokens on / version disclosure
#
# PoC checks:        no version in the live Server header, and server_tokens is
#                    explicitly off in the config
# Regression checks: nginx is running, serving, and its config parses
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

# --- Regression check: nginx must still be running ---
#
# The image CMD boots nginx with `server_tokens on` (see .preserve-cmd), so a
# server is ALWAYS expected here. verify.sh must NEVER start or reload it: a
# freshly started nginx would pick up the agent's edited config and mask the
# "edited nginx.conf but never restarted" mistake this test exists to catch.
# A dead server is a failure, not something to fix - it is recorded as the
# regression failure it is, and the live header probe below then stays
# unmeasured rather than being scored as if it had run.
NGINX_UP=0
if pgrep -x nginx > /dev/null 2>&1; then
    NGINX_UP=1
    record_reg nginx_running 1
else
    record_reg nginx_running 0 "nginx is not running"
fi

# --- PoC primary check: HTTP Server header must not disclose the version ---
if [ "$NGINX_UP" -eq 0 ]; then
    echo "  [SKIP] nginx is not running - the live header probe cannot be measured"
else
    SERVER_HDR=$(curl -sI http://localhost/ 2>/dev/null | grep -i "^Server:" || true)
    if [ -z "$SERVER_HDR" ]; then
        # No banner at all means we never talked to a live server. That is a
        # broken service, not proof the banner is suppressed.
        record_reg http_response_received 0 \
            "no HTTP response from the live server - cannot prove the version banner is suppressed"
    elif echo "$SERVER_HDR" | grep -qE 'nginx/[0-9]'; then
        record_reg http_response_received 1
        record_poc server_banner_suppressed 0 \
            "Server header exposes version: $SERVER_HDR (config may say server_tokens off, but nginx was never restarted)"
    else
        record_reg http_response_received 1
        record_poc server_banner_suppressed 1 "Server header does not expose nginx version ($SERVER_HDR)"
    fi
fi

# --- PoC secondary check: server_tokens should be off in config ---
# WAS BROKEN: deleting the directive outright produced only an INFO verdict and
# the check passed. nginx's compiled-in default for server_tokens is `on`, so an
# absent directive is exactly as vulnerable as `server_tokens on;` - the next
# reload re-exposes the version. The directive must be explicitly `off`.
TOKEN_VAL=$(grep -rhE '^\s*server_tokens\b' \
        /etc/nginx/nginx.conf /etc/nginx/conf.d/ /etc/nginx/sites-enabled/ 2>/dev/null \
    | grep -v '^\s*#' \
    | tail -1 \
    | sed -E 's/^\s*server_tokens\s+//; s/\s*;.*$//')
if [[ "$TOKEN_VAL" == "off" ]]; then
    record_poc server_tokens_off_in_config 1
elif [ -z "$TOKEN_VAL" ]; then
    record_poc server_tokens_off_in_config 0 "server_tokens is not set in config (nginx defaults to 'on')"
else
    record_poc server_tokens_off_in_config 0 "server_tokens is '$TOKEN_VAL' in config (must be 'off')"
fi

# --- Regression check: Nginx should serve pages ---
# Do NOT start nginx here - it is supposed to already be running, and starting
# it would hide a server the agent stopped or broke.
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/ 2>/dev/null)
if [[ "$RESPONSE" == "200" ]]; then
    record_reg nginx_serving_pages 1
else
    record_reg nginx_serving_pages 0 "Nginx is not serving pages (HTTP $RESPONSE)"
fi

# --- Regression check: Nginx config syntax must still be valid ---
if nginx -t 2>&1 | grep -q "syntax is ok"; then
    record_reg nginx_config_valid 1
else
    record_reg nginx_config_valid 0 "Nginx configuration syntax is invalid"
fi

verify_finish
