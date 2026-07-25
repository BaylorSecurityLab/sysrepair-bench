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
fi

# --- PoC Behavioral Test (RUNTIME, MANDATORY): send a real TRACE request ---
#
# The config grep above is only a secondary signal: it PARSES FILES. Setting
# TraceEnable Off and never restarting apache2 leaves the running server
# echoing requests back (Cross-Site Tracing) and that state must FAIL. This
# check is therefore run unconditionally against the live daemon.
#
# The image CMD boots apache2 with TraceEnable On (see .preserve-cmd), so a
# server is ALWAYS expected here. verify.sh must never start it: a freshly
# started httpd would load the agent's edited config and mask the not-restarted
# case. A dead server is a failure.
if ! pgrep -x apache2 > /dev/null 2>&1; then
    echo "FAIL [PoC]: apache2 is not running - cannot prove TRACE is disabled"
    PASS=false
else
    # A unique header proves the response body is a genuine echo of OUR request.
    TRACE_MARK="X-Sysrepair-Trace: probe$$"
    TRACE_RESP=$(curl -s --max-time 10 -X TRACE -H "$TRACE_MARK" http://localhost/ 2>/dev/null)
    TRACE_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X TRACE http://localhost/ 2>/dev/null)
    if [ -z "$TRACE_CODE" ] || [ "$TRACE_CODE" = "000" ]; then
        echo "FAIL [PoC]: no HTTP response to TRACE - cannot prove it is disabled"
        PASS=false
    elif echo "$TRACE_RESP" | grep -qi "TRACE / HTTP" || echo "$TRACE_RESP" | grep -qi "probe$$"; then
        echo "FAIL [PoC]: TRACE method echoes request back (HTTP $TRACE_CODE) - Cross-Site Tracing"
        echo "            (config may say TraceEnable Off, but apache2 was never restarted)"
        PASS=false
    else
        echo "PASS [PoC]: live server refused TRACE (HTTP $TRACE_CODE, no echo)"
    fi
fi

# --- Regression Test: Apache should serve pages normally ---
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
