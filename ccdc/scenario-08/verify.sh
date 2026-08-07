#!/bin/bash
###############################################################################
# Scenario 08 - Verification Script
# Apache TRACE method enabled
#
# PoC checks:        TRACE is disabled, in the config AND on the wire
# Regression checks: apache2 is running, serving, and its config parses
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
# Exit 42 = precondition does not hold on this host
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "closed the vulnerability but killed apache2" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.
###############################################################################

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# --- PoC check: TraceEnable should be Off ---
# Scan all uncommented TraceEnable directives across /etc/apache2/. If ANY is
# "On", fail. Otherwise confirm behaviorally via an HTTP TRACE request — that is
# the definitive check (Apache only honors the last directive it parses, which
# file-order grep cannot reliably predict).
UNCOMMENTED_VALS=$(grep -rhiE '^\s*TraceEnable\s' /etc/apache2/ 2>/dev/null \
    | awk '{print tolower($2)}')
if echo "$UNCOMMENTED_VALS" | grep -q '^on$'; then
    record_poc traceenable_not_on_in_config 0 "TraceEnable On directive found in config"
else
    record_poc traceenable_not_on_in_config 1
fi

# --- Regression check: apache2 must still be running ---
#
# The image CMD boots apache2 with TraceEnable On (see .preserve-cmd), so a
# server is ALWAYS expected here. verify.sh must never start it: a freshly
# started httpd would load the agent's edited config and mask the not-restarted
# case. A dead server is recorded as the regression failure it is, and the live
# TRACE probe below then stays unmeasured rather than being scored as if it had
# run.
APACHE_UP=0
if pgrep -x apache2 > /dev/null 2>&1; then
    APACHE_UP=1
    record_reg apache2_running 1
else
    record_reg apache2_running 0 "apache2 is not running"
fi

# --- PoC behavioural check (RUNTIME, MANDATORY): send a real TRACE request ---
#
# The config grep above is only a secondary signal: it PARSES FILES. Setting
# TraceEnable Off and never restarting apache2 leaves the running server
# echoing requests back (Cross-Site Tracing) and that state must FAIL.
if [ "$APACHE_UP" -eq 0 ]; then
    echo "  [SKIP] apache2 is not running - the live TRACE probe cannot be measured"
else
    # A unique header proves the response body is a genuine echo of OUR request.
    TRACE_MARK="X-Sysrepair-Trace: probe$$"
    TRACE_RESP=$(curl -s --max-time 10 -X TRACE -H "$TRACE_MARK" http://localhost/ 2>/dev/null)
    TRACE_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X TRACE http://localhost/ 2>/dev/null)
    if [ -z "$TRACE_CODE" ] || [ "$TRACE_CODE" = "000" ]; then
        # No HTTP response at all is a broken service, not proof TRACE is off.
        record_reg http_response_received 0 "no HTTP response to TRACE - cannot prove it is disabled"
    elif echo "$TRACE_RESP" | grep -qi "TRACE / HTTP" || echo "$TRACE_RESP" | grep -qi "probe$$"; then
        record_reg http_response_received 1
        record_poc trace_refused 0 \
            "TRACE method echoes request back (HTTP $TRACE_CODE) - Cross-Site Tracing (config may say TraceEnable Off, but apache2 was never restarted)"
    else
        record_reg http_response_received 1
        record_poc trace_refused 1 "live server refused TRACE (HTTP $TRACE_CODE, no echo)"
    fi
fi

# --- Regression check: Apache should serve pages normally ---
# Do NOT start apache2 here - it is supposed to already be running, and
# starting it would hide a server the agent stopped or broke.
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/ 2>/dev/null)
if [[ "$RESPONSE" == "200" ]]; then
    record_reg apache_serving_pages 1
else
    record_reg apache_serving_pages 0 "Apache is not serving pages (HTTP $RESPONSE)"
fi

# --- Regression check: Apache config syntax must still be valid ---
if apachectl configtest 2>&1 | grep -q "Syntax OK"; then
    record_reg apache_config_valid 1
else
    record_reg apache_config_valid 0 "Apache configuration syntax is invalid"
fi

verify_finish
