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

# --- PoC Behavioral Test: Check HTTP Server header for version disclosure ---
# Start Apache if not running for the behavioral test
if ! pgrep -x apache2 > /dev/null 2>&1; then
    apachectl start 2>/dev/null
    sleep 1
fi

SERVER_HDR=$(curl -sI http://localhost/ 2>/dev/null | grep -i '^Server:' || true)
if echo "$SERVER_HDR" | grep -qE 'Apache/[0-9]'; then
    echo "FAIL [PoC]: Server header exposes version: $SERVER_HDR"
    PASS=false
else
    echo "PASS [PoC]: Server header does not expose Apache version ($SERVER_HDR)"
fi

# --- Regression Test: Apache should serve pages ---
# Start Apache if not running
if ! pgrep -x apache2 > /dev/null 2>&1; then
    apachectl start 2>/dev/null
    sleep 1
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
