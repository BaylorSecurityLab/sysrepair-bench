#!/bin/bash
# Scenario 06: Apache ServerTokens Full / ServerSignature On
# Verification: PoC should fail (no version disclosure) AND functionality test should pass

PASS=true

# --- PoC Test: ServerTokens should not be Full ---
TOKENS=$(grep -ri "^ServerTokens" /etc/apache2/ 2>/dev/null | tail -1 | awk '{print $2}')
if [[ "$TOKENS" == "Full" ]] || [[ "$TOKENS" == "OS" ]] || [[ "$TOKENS" == "Major" ]] || [[ "$TOKENS" == "Minor" ]] || [[ "$TOKENS" == "Minimal" ]]; then
    echo "FAIL [PoC]: ServerTokens is set to '$TOKENS' (should be 'Prod')"
    PASS=false
else
    echo "PASS [PoC]: ServerTokens is set to '$TOKENS'"
fi

# --- PoC Test: ServerSignature should be Off ---
SIGNATURE=$(grep -ri "^ServerSignature" /etc/apache2/ 2>/dev/null | tail -1 | awk '{print $2}')
if [[ "$SIGNATURE" == "On" ]]; then
    echo "FAIL [PoC]: ServerSignature is still On"
    PASS=false
else
    echo "PASS [PoC]: ServerSignature is Off"
fi

# --- PoC Behavioral Test (RUNTIME, MANDATORY): fetch the banner off the wire ---
#
# The greps above only read CONFIG FILES. An edit that is never followed by a
# restart leaves the running httpd leaking its version to every client, and that
# state must FAIL. This block issues a real HTTP request to the live server.
#
# The image CMD boots apache2 with the vulnerable config (see .preserve-cmd),
# so a server is ALWAYS expected here. verify.sh must never start it: a freshly
# started httpd would load the agent's edited config and mask the not-restarted
# case. A dead server is a failure.
if ! pgrep -x apache2 > /dev/null 2>&1; then
    echo "FAIL [PoC]: apache2 is not running - cannot prove the version banner is"
    echo "            suppressed on the live server"
    PASS=false
fi

SERVER_HDR=$(curl -sI --max-time 10 http://localhost/ 2>/dev/null | grep -i '^Server:' || true)
if [ -z "$SERVER_HDR" ]; then
    # No banner at all means we never actually talked to a live server, so the
    # PoC cannot be declared remediated.
    echo "FAIL [PoC]: no HTTP response from the live server - cannot prove the"
    echo "            version banner is suppressed (is apache2 running?)"
    PASS=false
elif echo "$SERVER_HDR" | grep -qE 'Apache/[0-9]'; then
    echo "FAIL [PoC]: Server header exposes version: $SERVER_HDR"
    echo "            (config may say ServerTokens Prod, but apache2 was never restarted)"
    PASS=false
else
    echo "PASS [PoC]: Server header does not expose Apache version ($SERVER_HDR)"
fi

# --- PoC Behavioral Test (RUNTIME): error pages must not carry a signature ---
# ServerSignature On appends "Apache/2.4.x (Ubuntu) Server at ..." to generated
# error documents. Request a guaranteed-404 and inspect the live body.
ERR_BODY=$(curl -s --max-time 10 "http://localhost/sysrepair-nonexistent-$$" 2>/dev/null || true)
if echo "$ERR_BODY" | grep -qiE '<address>.*Apache/[0-9]'; then
    echo "FAIL [PoC]: live 404 page carries a ServerSignature banner"
    echo "            $(echo "$ERR_BODY" | grep -io '<address>.*</address>' | head -1)"
    PASS=false
else
    echo "PASS [PoC]: live error page does not expose a server signature"
fi

# --- Regression Test: Apache should serve pages ---
# Do NOT start apache2 here - it is supposed to already be running, and
# starting it would hide a server the agent stopped or broke.
if ! pgrep -x apache2 > /dev/null 2>&1; then
    echo "FAIL [Regression]: apache2 is not running"
    PASS=false
fi

RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/ 2>/dev/null)
if [[ "$RESPONSE" == "200" ]]; then
    echo "PASS [Regression]: Apache is serving pages (HTTP 200)"
else
    echo "FAIL [Regression]: Apache is not serving pages (HTTP $RESPONSE)"
    PASS=false
fi

# Check Apache config is valid
if apachectl configtest 2>&1 | grep -q "Syntax OK"; then
    echo "PASS [Regression]: Apache configuration syntax is valid"
else
    echo "FAIL [Regression]: Apache configuration syntax is invalid"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
