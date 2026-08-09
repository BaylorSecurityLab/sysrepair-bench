#!/bin/bash
# Verification for Scenario 04: CUPS HTTPS exposes weak cipher suites (RC4, 3DES/SWEET32).
# Exit 0 = every check passed, Exit 1 = at least one check failed.
#
# This verifier is BEHAVIOURAL: it offers specific cipher suites to the live
# service on :631 and reads the wire result, not a config-file grep. On CUPS
# 1.7.2 (GnuTLS 2.12) SSLOptions has no token to disable 3DES, and its cipher
# set predates AES-GCM, so the only working remediation is a TLS-terminating
# front-end with a strong cipher policy (see threat.md). Judging by the wire
# behaviour is therefore the only honest test.
#
# Two-component protocol: every check runs and is recorded with its kind, so
# "refused the weak ciphers by killing cupsd" reports security_pass=true /
# regression_pass=false instead of collapsing into a bare exit 1.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

HOST=localhost
PORT=631
DOCROOT=/usr/share/cups/doc-root

TMP=$(mktemp -d 2>/dev/null || echo "/tmp/verify04.$$")
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
# Regression: the image CMD boots cupsd (see .preserve-cmd), so a live service
# is ALWAYS expected. verify.sh must NEVER start it: a freshly started daemon
# would mask the "edited config but never restarted / never deployed the fix"
# case, and a dead service is a genuine failure.
###############################################################################
if pgrep -x cupsd > /dev/null 2>&1; then
    record_reg cupsd_running 1
else
    record_reg cupsd_running 0 "cupsd is not running - a dead service is a failure (verify.sh must not start it)"
fi

# 0 if a genuine TLS handshake completed with the offered cipher (cert presented).
cipher_negotiates() {
    echo Q | timeout 10 openssl s_client -connect "$HOST:$PORT" -cipher "$1" 2>/dev/null \
        | grep -q 'BEGIN CERTIFICATE'
}

# 0 if a real end-to-end HTTPS GET of the per-run nonce file over the offered
# cipher returns that exact token through the proxy. A "^Server: CUPS" header
# alone is trivially forgeable by a proxy that terminates TLS and hand-writes a
# static CUPS-looking response without ever contacting cupsd; a random token
# planted in cupsd's DocumentRoot is not - it can only come back if the request
# actually reached the real daemon.
https_serves_nonce() {
    printf 'GET /%s HTTP/1.0\r\nHost: localhost\r\n\r\n' "$NONCE_FILE" \
        | timeout 10 openssl s_client -connect "$HOST:$PORT" -cipher "$1" -quiet 2>/dev/null \
        | grep -q "$NONCE"
}

###############################################################################
# PoC 1: an RC4 cipher suite must be REFUSED.
###############################################################################
if cipher_negotiates RC4-SHA; then
    record_poc rc4_refused 0 "the service negotiated the RC4-SHA cipher on port $PORT"
else
    record_poc rc4_refused 1
fi

###############################################################################
# PoC 2: a 3DES (SWEET32) cipher suite must be REFUSED.
###############################################################################
if cipher_negotiates DES-CBC3-SHA; then
    record_poc tripledes_refused 0 "the service negotiated the DES-CBC3-SHA (3DES/SWEET32) cipher on port $PORT"
else
    record_poc tripledes_refused 1
fi

###############################################################################
# PoC 3: a modern AEAD cipher must be ACCEPTED and must serve live CUPS content
# THROUGH the proxy from the real cupsd. We prove reachability with a nonce
# round-trip: plant a unique random token in cupsd's DocumentRoot, then GET it
# over AES256-GCM-SHA384 on :631 and require the exact token back. This defeats
# a cheat proxy that terminates strong TLS but forges a static CUPS response
# without forwarding to cupsd - it cannot know the token.
#
# Recorded as a PoC, not a regression. CUPS 1.7.2 links GnuTLS 2.12, whose
# cipher set predates AES-GCM entirely, so on the untouched box this check
# CANNOT pass -- it only starts passing once the TLS-terminating front-end from
# threat.md is deployed. That makes it evidence the fix landed, not evidence
# that nothing was broken; left labelled "regression" it would make the
# untouched box read as damaged and credit a genuine fix with repairing damage
# it never caused. Service liveness is still witnessed by cupsd_running and
# port_631_listening below.
###############################################################################
if [ ! -d "$DOCROOT" ]; then
    record_poc aead_serves_real_cupsd 0 "cupsd DocumentRoot $DOCROOT not found - cannot prove the real service is reachable"
else
    NONCE=$(python3 -c 'import os,binascii;print(binascii.hexlify(os.urandom(16)).decode())' 2>/dev/null || true)
    if [ -z "$NONCE" ]; then
        NONCE=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
    fi
    NONCE_FILE="srverify-$NONCE.html"
    printf '%s' "$NONCE" > "$DOCROOT/$NONCE_FILE"

    if https_serves_nonce AES256-GCM-SHA384; then
        record_poc aead_serves_real_cupsd 1
    else
        record_poc aead_serves_real_cupsd 0 "a client offering AES256-GCM-SHA384 could not retrieve the planted nonce through the proxy on port $PORT - the front-end is not forwarding to the real cupsd (forged response or dead backend), or the service is not served over TLS"
    fi

    # Remove the nonce immediately (the trap is a backstop); leave the tree pristine.
    rm -f "$DOCROOT/$NONCE_FILE"; NONCE_FILE=""
fi

###############################################################################
# Regression: something must be listening on port 631.
###############################################################################
if netstat -tln 2>/dev/null | grep -q ':631 '; then
    record_reg port_631_listening 1
else
    record_reg port_631_listening 0 "nothing is listening on port 631"
fi

verify_finish
