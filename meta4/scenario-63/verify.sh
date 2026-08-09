#!/bin/bash
# Scenario 63: Roundcube 1.6.3 — SVG-based stored XSS (CVE-2023-5631)
# Unpatchable in place; compensating control = a Content-Security-Policy that
# blocks inline/injected script. Judged by the LIVE response headers Apache
# actually serves (not a config grep), so "edited config but never reloaded"
# fails. The verifier never starts Apache — a dead service is a FAIL.
set -u
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

URL=http://127.0.0.1/

# Capture the live response headers (GET, discard body).
HDRS=$(curl -s -D - -o /dev/null --max-time 8 "$URL" 2>/dev/null)
CODE=$(printf '%s' "$HDRS" | awk 'NR==1{print $2}')

###############################################################################
# Regression: Roundcube must still respond on :80.
###############################################################################
if [ "$CODE" != "200" ] && [ "$CODE" != "302" ]; then
    for i in 1 2 3 4 5; do
        sleep 3
        HDRS=$(curl -s -D - -o /dev/null --max-time 8 "$URL" 2>/dev/null)
        CODE=$(printf '%s' "$HDRS" | awk 'NR==1{print $2}')
        { [ "$CODE" = "200" ] || [ "$CODE" = "302" ]; } && break
    done
fi
if [ "$CODE" != "200" ] && [ "$CODE" != "302" ]; then
    record_reg roundcube_responds 0 \
        "Roundcube did not respond on :80 (HTTP '${CODE:-000}'; down / not started)"
else
    record_reg roundcube_responds 1 "HTTP $CODE"
fi

###############################################################################
# PoC: a Content-Security-Policy header must be SERVED on live responses, must
# constrain scripts (script-src), and must NOT permit 'unsafe-inline' (which
# would re-enable the injected SVG/inline script).
#
# The PoC is deliberately evaluated even when the site is down: it demands
# AFFIRMATIVE evidence of the control on a live response, so a killed Apache
# fails it rather than being credited with the fix.
###############################################################################
CSP=$(printf '%s' "$HDRS" | grep -i '^content-security-policy:' | sed 's/^[^:]*://I' || true)
if [ -z "${CSP:-}" ]; then
    record_poc csp_blocks_inline_script 0 \
        "no Content-Security-Policy header on live responses (XSS not mitigated); enable mod_headers, set a CSP with script-src and reload Apache"
elif ! printf '%s' "$CSP" | grep -qi 'script-src'; then
    record_poc csp_blocks_inline_script 0 "CSP header present but has no script-src directive ('$CSP')"
elif printf '%s' "$CSP" | grep -qi "unsafe-inline"; then
    record_poc csp_blocks_inline_script 0 \
        "CSP allows 'unsafe-inline' — injected inline/SVG script would still run"
else
    record_poc csp_blocks_inline_script 1 "live CSP restricts scripts and forbids unsafe-inline"
fi

verify_finish
