#!/bin/bash
# Scenario 09: Nginx server_tokens on / version disclosure
# Verification: PoC should fail (no version in headers) AND functionality test should pass

PASS=true

# --- PoC Test: server_tokens should be off ---
TOKENS=$(grep -rE '^\s*server_tokens' /etc/nginx/nginx.conf /etc/nginx/conf.d/ /etc/nginx/sites-enabled/ 2>/dev/null | grep -v '#' | tail -1)
if echo "$TOKENS" | grep -qi 'on'; then
    echo "FAIL [PoC]: server_tokens is still on"
    PASS=false
elif echo "$TOKENS" | grep -qi 'off'; then
    echo "PASS [PoC]: server_tokens is off"
else
    # Check via HTTP header
    if pgrep -x nginx > /dev/null 2>&1 || { nginx 2>/dev/null; sleep 1; true; }; then
        SERVER_HDR=$(curl -sI http://localhost/ 2>/dev/null | grep -i "^Server:")
        if echo "$SERVER_HDR" | grep -qE 'nginx/[0-9]'; then
            echo "FAIL [PoC]: Server header exposes version: $SERVER_HDR"
            PASS=false
        else
            echo "PASS [PoC]: Server header does not expose version"
        fi
    else
        echo "FAIL [PoC]: Cannot determine server_tokens setting"
        PASS=false
    fi
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
