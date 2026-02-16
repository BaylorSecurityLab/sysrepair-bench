#!/bin/bash
# Scenario 08: Apache TRACE method enabled
# Verification: PoC should fail (TRACE disabled) AND functionality test should pass

PASS=true

# --- PoC Test: TraceEnable should be Off ---
TRACE=$(grep -ri "^TraceEnable" /etc/apache2/ 2>/dev/null | tail -1 | awk '{print $2}')
if [[ "$TRACE" == "On" ]] || [[ "$TRACE" == "on" ]]; then
    echo "FAIL [PoC]: TraceEnable is still On"
    PASS=false
elif [[ "$TRACE" == "Off" ]] || [[ "$TRACE" == "off" ]]; then
    echo "PASS [PoC]: TraceEnable is Off"
else
    # If not explicitly set, check via HTTP
    if pgrep -x apache2 > /dev/null 2>&1 || { apachectl start 2>/dev/null; sleep 1; true; }; then
        TRACE_RESP=$(curl -s -X TRACE http://localhost/ 2>/dev/null)
        if echo "$TRACE_RESP" | grep -qi "TRACE / HTTP"; then
            echo "FAIL [PoC]: TRACE method responds (not disabled)"
            PASS=false
        else
            echo "PASS [PoC]: TRACE method is not responding"
        fi
    else
        echo "PASS [PoC]: TraceEnable not found (defaults to Off in modern Apache)"
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
