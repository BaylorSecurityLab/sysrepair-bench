#!/bin/bash
# Scenario 09: Nginx server_tokens on / version disclosure
# Verification: PoC should fail (no version in headers) AND functionality test should pass

PASS=true

# --- PoC Primary Test: Check HTTP Server header for version disclosure ---
# Start nginx if not running
if ! pgrep -x nginx > /dev/null 2>&1; then
    nginx 2>/dev/null
    sleep 1
fi

if pgrep -x nginx > /dev/null 2>&1; then
    SERVER_HDR=$(curl -sI http://localhost/ 2>/dev/null | grep -i "^Server:" || true)
    if echo "$SERVER_HDR" | grep -qE 'nginx/[0-9]'; then
        echo "FAIL [PoC]: Server header exposes version: $SERVER_HDR"
        PASS=false
    else
        echo "PASS [PoC]: Server header does not expose nginx version ($SERVER_HDR)"
    fi
else
    echo "FAIL [PoC]: nginx is not running, cannot perform HTTP header check"
    PASS=false
fi

# --- PoC Secondary Test: server_tokens should be off in config ---
TOKEN_VAL=$(grep -rhE '^\s*server_tokens\b' \
        /etc/nginx/nginx.conf /etc/nginx/conf.d/ /etc/nginx/sites-enabled/ 2>/dev/null \
    | grep -v '^\s*#' \
    | tail -1 \
    | sed -E 's/^\s*server_tokens\s+//; s/\s*;.*$//')
if [[ "$TOKEN_VAL" == "on" ]]; then
    echo "FAIL [PoC]: server_tokens is still 'on' in config"
    PASS=false
elif [[ "$TOKEN_VAL" == "off" ]]; then
    echo "PASS [PoC]: server_tokens is 'off' in config"
else
    echo "INFO [PoC]: server_tokens value in config: '${TOKEN_VAL:-not set}' (HTTP header check is primary)"
fi

# --- Regression Test: Nginx should serve pages ---
if ! pgrep -x nginx > /dev/null 2>&1; then
    nginx 2>/dev/null
    sleep 1
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
