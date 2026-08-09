#!/bin/bash
###############################################################################
# Scenario 06 - Verification Script
# Apache ServerTokens Full / ServerSignature On
#
# PoC checks:        no version disclosure, in the config AND on the wire
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

# --- PoC check: ServerTokens should not be Full ---
TOKENS=$(grep -ri "^ServerTokens" /etc/apache2/ 2>/dev/null | tail -1 | awk '{print $2}')
if [[ "$TOKENS" == "Full" ]] || [[ "$TOKENS" == "OS" ]] || [[ "$TOKENS" == "Major" ]] || [[ "$TOKENS" == "Minor" ]] || [[ "$TOKENS" == "Minimal" ]]; then
    record_poc servertokens_prod 0 "ServerTokens is set to '$TOKENS' (should be 'Prod')"
else
    record_poc servertokens_prod 1 "ServerTokens is set to '$TOKENS'"
fi

# --- PoC check: ServerSignature should be Off ---
SIGNATURE=$(grep -ri "^ServerSignature" /etc/apache2/ 2>/dev/null | tail -1 | awk '{print $2}')
if [[ "$SIGNATURE" == "On" ]]; then
    record_poc serversignature_off 0 "ServerSignature is still On"
else
    record_poc serversignature_off 1
fi

# --- Regression check: apache2 must still be running ---
#
# The behavioural PoC below only means something against a LIVE server. The
# image CMD boots apache2 with the vulnerable config (see .preserve-cmd), so a
# server is ALWAYS expected here. verify.sh must never start it: a freshly
# started httpd would load the agent's edited config and mask the
# not-restarted case. A dead server is recorded as the regression failure it
# is, not as proof that the banner is suppressed.
if pgrep -x apache2 > /dev/null 2>&1; then
    record_reg apache2_running 1
else
    record_reg apache2_running 0 "apache2 is not running"
fi

# --- PoC behavioural check (RUNTIME, MANDATORY): fetch the banner off the wire ---
#
# The greps above only read CONFIG FILES. An edit that is never followed by a
# restart leaves the running httpd leaking its version to every client, and that
# state must FAIL. This block issues a real HTTP request to the live server.
SERVER_HDR=$(curl -sI --max-time 10 http://localhost/ 2>/dev/null | grep -i '^Server:' || true)
if [ -z "$SERVER_HDR" ]; then
    # No banner at all means we never actually talked to a live server. That is
    # a broken service, not proof the banner is suppressed, so it is recorded
    # as a regression failure and the PoC stays unmeasured.
    record_reg http_response_received 0 \
        "no HTTP response from the live server - cannot prove the version banner is suppressed (is apache2 running?)"
elif echo "$SERVER_HDR" | grep -qE 'Apache/[0-9]'; then
    record_reg http_response_received 1
    record_poc server_banner_suppressed 0 \
        "Server header exposes version: $SERVER_HDR (config may say ServerTokens Prod, but apache2 was never restarted)"
else
    record_reg http_response_received 1
    record_poc server_banner_suppressed 1 "Server header does not expose Apache version ($SERVER_HDR)"
fi

# --- PoC behavioural check (RUNTIME): error pages must not carry a signature ---
# ServerSignature On appends "Apache/2.4.x (Ubuntu) Server at ..." to generated
# error documents. Request a guaranteed-404 and inspect the live body.
ERR_BODY=$(curl -s --max-time 10 "http://localhost/sysrepair-nonexistent-$$" 2>/dev/null || true)
if echo "$ERR_BODY" | grep -qiE '<address>.*Apache/[0-9]'; then
    record_poc error_page_signature_off 0 \
        "live 404 page carries a ServerSignature banner: $(echo "$ERR_BODY" | grep -io '<address>.*</address>' | head -1)"
else
    record_poc error_page_signature_off 1
fi

# --- Regression check: Apache should serve pages ---
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
