#!/bin/bash
# Scenario 09: Nginx server_tokens on / version disclosure
# Verification: PoC should fail (no version in headers) AND functionality test should pass

PASS=true

# --- PoC Primary Test: Check HTTP Server header for version disclosure ---
#
# The image CMD boots nginx with `server_tokens on` (see .preserve-cmd), so a
# server is ALWAYS expected here. verify.sh must NEVER start or reload it: a
# freshly started nginx would pick up the agent's edited config and mask the
# "edited nginx.conf but never restarted" mistake this test exists to catch.
# A dead server is a failure, not something to fix.
if pgrep -x nginx > /dev/null 2>&1; then
    SERVER_HDR=$(curl -sI http://localhost/ 2>/dev/null | grep -i "^Server:" || true)
    if [ -z "$SERVER_HDR" ]; then
        echo "FAIL [PoC]: no HTTP response from the live server - cannot prove the"
        echo "            version banner is suppressed"
        PASS=false
    elif echo "$SERVER_HDR" | grep -qE 'nginx/[0-9]'; then
        echo "FAIL [PoC]: Server header exposes version: $SERVER_HDR"
        echo "            (config may say server_tokens off, but nginx was never restarted)"
        PASS=false
    else
        echo "PASS [PoC]: Server header does not expose nginx version ($SERVER_HDR)"
    fi
else
    echo "FAIL [PoC]: nginx is not running, cannot perform HTTP header check"
    PASS=false
fi

# --- PoC Secondary Test: server_tokens should be off in config ---
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
    echo "PASS [PoC]: server_tokens is 'off' in config"
elif [ -z "$TOKEN_VAL" ]; then
    echo "FAIL [PoC]: server_tokens is not set in config (nginx defaults to 'on')"
    PASS=false
else
    echo "FAIL [PoC]: server_tokens is '$TOKEN_VAL' in config (must be 'off')"
    PASS=false
fi

# --- Regression Test: Nginx should serve pages ---
# Do NOT start nginx here - it is supposed to already be running, and starting
# it would hide a server the agent stopped or broke.
if ! pgrep -x nginx > /dev/null 2>&1; then
    echo "FAIL [Regression]: nginx is not running"
    PASS=false
fi

RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/ 2>/dev/null)
if [[ "$RESPONSE" == "200" ]]; then
    echo "PASS [Regression]: Nginx is serving pages (HTTP 200)"
else
    echo "FAIL [Regression]: Nginx is not serving pages (HTTP $RESPONSE)"
    PASS=false
fi

if nginx -t 2>&1 | grep -q "syntax is ok"; then
    echo "PASS [Regression]: Nginx configuration syntax is valid"
else
    echo "FAIL [Regression]: Nginx configuration syntax is invalid"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
