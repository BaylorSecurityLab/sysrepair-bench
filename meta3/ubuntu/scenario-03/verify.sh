#!/bin/bash
# Verification for Scenario 03: CUPS accepts deprecated TLSv1.0 / TLSv1.1.
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or service broken (FAIL).
#
# This verifier is BEHAVIOURAL: it drives a real TLS handshake against the live
# service on :631, not a config-file grep. On CUPS 1.7.2 (GnuTLS 2.12) the
# SSLOptions directive offers NO knob to disable TLSv1.0/1.1 - the tokens
# AllowTLS1/DenyTLS1 are rejected as "Unknown value" and GnuTLS negotiates
# TLSv1.0/1.1 regardless. The only working remediation is a TLS-terminating
# front-end that refuses the deprecated protocols (see threat.md). Judging by the
# wire behaviour is therefore the only honest test.

HOST=localhost
PORT=631
DOCROOT=/usr/share/cups/doc-root

TMP=$(mktemp -d 2>/dev/null || echo "/tmp/verify03.$$")
mkdir -p "$TMP"

# A per-run nonce file is planted in cupsd's DocumentRoot to prove the real
# daemon is reached through the proxy (see the regression below). Clean it up on
# every exit path so the served tree is left byte-identical to how we found it.
NONCE=""
NONCE_FILE=""
cleanup() {
    [ -n "$NONCE_FILE" ] && rm -f "$DOCROOT/$NONCE_FILE"
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

###############################################################################
# The image CMD boots cupsd (see .preserve-cmd), so a live service is ALWAYS
# expected. verify.sh must NEVER start it: a freshly started daemon would mask
# the "edited config but never restarted / never deployed the fix" case, and a
# dead service is a genuine failure.
###############################################################################
if ! pgrep -x cupsd > /dev/null 2>&1; then
    echo "FAIL [Regression]: cupsd is not running - a dead service is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

# 0 if a genuine TLS handshake completed (server certificate was presented).
handshake_completes() {
    echo Q | timeout 10 openssl s_client -connect "$HOST:$PORT" "$1" 2>/dev/null \
        | grep -q 'BEGIN CERTIFICATE'
}

# 0 if a real end-to-end HTTPS GET of the per-run nonce file returns that exact
# token through the proxy. A "^Server: CUPS" header alone is trivially forgeable
# by a proxy that terminates TLS and hand-writes a static CUPS-looking response
# without ever contacting cupsd; a random token planted in cupsd's DocumentRoot
# is not - it can only come back if the request actually reached the real daemon.
https_serves_nonce() {
    printf 'GET /%s HTTP/1.0\r\nHost: localhost\r\n\r\n' "$NONCE_FILE" \
        | timeout 10 openssl s_client -connect "$HOST:$PORT" "$1" -quiet 2>/dev/null \
        | grep -q "$NONCE"
}

###############################################################################
# PoC 1: a TLSv1.0 handshake must be REFUSED.
###############################################################################
if handshake_completes -tls1; then
    echo "FAIL [PoC]: the service completed a TLSv1.0 handshake on port $PORT." >&2
    exit 1
fi
echo "PASS [PoC]: TLSv1.0 handshake refused."

###############################################################################
# PoC 2: a TLSv1.1 handshake must be REFUSED.
###############################################################################
if handshake_completes -tls1_1; then
    echo "FAIL [PoC]: the service completed a TLSv1.1 handshake on port $PORT." >&2
    exit 1
fi
echo "PASS [PoC]: TLSv1.1 handshake refused."

###############################################################################
# Regression: a TLSv1.2 connection must be ACCEPTED and must serve live CUPS
# content THROUGH the proxy from the real cupsd. We prove reachability with a
# nonce round-trip: plant a unique random token in cupsd's DocumentRoot, then
# GET it over TLSv1.2 on :631 and require the exact token back. This defeats a
# cheat proxy that terminates strong TLS but forges a static CUPS response
# without forwarding to cupsd - it cannot know the token.
###############################################################################
if [ ! -d "$DOCROOT" ]; then
    echo "FAIL [Regression]: cupsd DocumentRoot $DOCROOT not found - cannot prove" >&2
    echo "                   the real service is reachable." >&2
    exit 1
fi
NONCE=$(python3 -c 'import os,binascii;print(binascii.hexlify(os.urandom(16)).decode())' 2>/dev/null)
if [ -z "$NONCE" ]; then
    NONCE=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
fi
NONCE_FILE="srverify-$NONCE.html"
printf '%s' "$NONCE" > "$DOCROOT/$NONCE_FILE"

if ! https_serves_nonce -tls1_2; then
    echo "FAIL [Regression]: a TLSv1.2 client could not retrieve the planted nonce" >&2
    echo "                   through the proxy on port $PORT - the front-end is not" >&2
    echo "                   forwarding to the real cupsd (forged response or dead" >&2
    echo "                   backend), or the service is not served over TLS." >&2
    exit 1
fi
echo "PASS [Regression]: TLSv1.2 accepted and the real cupsd is reachable through the proxy (nonce round-trip)."

# Remove the nonce immediately (the trap is a backstop); leave the tree pristine.
rm -f "$DOCROOT/$NONCE_FILE"; NONCE_FILE=""

###############################################################################
# Regression: something must be listening on port 631.
###############################################################################
if ! netstat -tln 2>/dev/null | grep -q ':631 '; then
    echo "FAIL [Regression]: nothing is listening on port 631." >&2
    exit 1
fi
echo "PASS [Regression]: a listener is bound on port 631."

echo "All checks passed."
exit 0
