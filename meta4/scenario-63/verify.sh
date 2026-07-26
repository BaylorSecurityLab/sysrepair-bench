#!/bin/bash
# Scenario 63: Roundcube 1.6.3 — SVG-based stored XSS (CVE-2023-5631)
# Unpatchable in place; compensating control = a Content-Security-Policy that
# blocks inline/injected script. Judged by the LIVE response headers Apache
# actually serves (not a config grep), so "edited config but never reloaded"
# fails. The verifier never starts Apache — a dead service is a FAIL.
set -u

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
    echo "FAIL [Regression]: Roundcube did not respond on :80 (HTTP '$CODE'; down / not started)." >&2
    exit 1
fi

###############################################################################
# PoC: a Content-Security-Policy header must be SERVED on live responses, must
# constrain scripts (script-src), and must NOT permit 'unsafe-inline' (which
# would re-enable the injected SVG/inline script).
###############################################################################
CSP=$(printf '%s' "$HDRS" | grep -i '^content-security-policy:' | sed 's/^[^:]*://I')
if [ -z "$CSP" ]; then
    echo "FAIL [PoC]: no Content-Security-Policy header on live responses (XSS not mitigated)." >&2
    echo "            Enable mod_headers, set a CSP with script-src, and reload Apache." >&2
    exit 1
fi
if ! printf '%s' "$CSP" | grep -qi 'script-src'; then
    echo "FAIL [PoC]: CSP header present but has no script-src directive ('$CSP')." >&2
    exit 1
fi
if printf '%s' "$CSP" | grep -qi "unsafe-inline"; then
    echo "FAIL [PoC]: CSP allows 'unsafe-inline' — injected inline/SVG script would still run." >&2
    exit 1
fi
echo "PASS [PoC]: live CSP header restricts scripts and forbids unsafe-inline."

echo "PASS [Regression]: Roundcube responds on :80 (HTTP $CODE)."
exit 0
