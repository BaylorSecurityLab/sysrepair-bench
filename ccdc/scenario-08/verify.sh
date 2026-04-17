#!/bin/bash
# Scenario 08: Apache TRACE method enabled
# Verification: PoC should fail (TRACE disabled) AND functionality test should pass

PASS=true

# --- PoC Test: TraceEnable should be Off ---
# Scan all uncommented TraceEnable directives across /etc/apache2/. If ANY is
# "On", fail. Otherwise confirm behaviorally via an HTTP TRACE request — that is
# the definitive check (Apache only honors the last directive it parses, which
# file-order grep cannot reliably predict).
UNCOMMENTED_VALS=$(grep -rhiE '^\s*TraceEnable\s' /etc/apache2/ 2>/dev/null \
    | awk '{print tolower($2)}')
if echo "$UNCOMMENTED_VALS" | grep -q '^on$'; then
    echo "FAIL [PoC]: TraceEnable On directive found in config"
    PASS=false
else
    if ! pgrep -x apache2 > /dev/null 2>&1; then
        apachectl start 2>/dev/null
        sleep 1
    fi
    TRACE_RESP=$(curl -s -X TRACE http://localhost/ 2>/dev/null)
    if echo "$TRACE_RESP" | grep -qi "TRACE / HTTP"; then
        echo "FAIL [PoC]: TRACE method echoes request (not disabled)"
        PASS=false
    else
        echo "PASS [PoC]: TRACE method is disabled"
    fi
fi

# --- Regression Test: Apache should serve pages normally ---
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
