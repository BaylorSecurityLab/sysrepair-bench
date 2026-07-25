#!/bin/bash
# Scenario 10: Nginx autoindex on (directory listing)
# Verification: PoC should fail (no directory listing) AND functionality test should pass

PASS=true

# --- PoC Test: autoindex should be off ---
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
    echo "FAIL [PoC]: autoindex is still enabled (directive value: on)"
    PASS=false
elif [ -z "$AUTOINDEX_VALUES" ]; then
    echo "PASS [PoC]: autoindex directive is not set (nginx default is off)"
else
    echo "PASS [PoC]: autoindex is explicitly disabled (directive value(s): $(echo $AUTOINDEX_VALUES | tr '\n' ' '))"
fi

# Also verify via HTTP — this is the behavioral test (mandatory)
#
# The image CMD boots nginx with `autoindex on` (see .preserve-cmd), so a server
# is ALWAYS expected here. verify.sh must NEVER start or reload it: a freshly
# started nginx would pick up the agent's edited config and mask the "edited the
# config but never restarted" mistake. A dead server is a failure.
if pgrep -x nginx > /dev/null 2>&1; then
    LISTING=$(curl -s http://localhost/files/ 2>/dev/null)
    LISTING_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://localhost/files/ 2>/dev/null)
    if [ -z "$LISTING_CODE" ] || [ "$LISTING_CODE" = "000" ]; then
        echo "FAIL [PoC]: no HTTP response for /files/ - cannot prove listing is off"
        PASS=false
    elif echo "$LISTING" | grep -qi "Index of /files"; then
        echo "FAIL [PoC]: Directory listing accessible via HTTP"
        echo "            (config may say autoindex off, but nginx was never restarted)"
        PASS=false
    else
        echo "PASS [PoC]: Directory listing not accessible via HTTP"
    fi
else
    echo "FAIL [PoC]: nginx is not running, cannot perform directory listing check"
    PASS=false
fi

# --- Regression Test: Nginx should serve the main page ---
# Do NOT start nginx here - it is supposed to already be running, and starting
# it would hide a server the agent stopped or broke.
if ! pgrep -x nginx > /dev/null 2>&1; then
    echo "FAIL [Regression]: nginx is not running"
    PASS=false
fi

RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/ 2>/dev/null)
if [[ "$RESPONSE" == "200" ]]; then
    echo "PASS [Regression]: Nginx is serving the main page (HTTP 200)"
else
    echo "FAIL [Regression]: Nginx is not serving the main page (HTTP $RESPONSE)"
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
