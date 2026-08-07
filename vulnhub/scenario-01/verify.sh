#!/bin/bash
# Verification: Scenario 01 - Apache deprecated SSL/TLS protocols (CWE-327)
# VulnHub Source: Kioptrix Level 1
#
# PoC checks:        the LIVE server refuses TLSv1.0/1.1 and weak RC4/3DES ciphers
# Regression checks: the LIVE server still completes a TLSv1.2 handshake
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
#
# Dynamic evidence: we speak TLS to the RUNNING server on :443 with openssl
# s_client (the only TLS tool present - curl/nc are absent) and require the
# deprecated protocols to be refused on the wire. This reflects the live daemon,
# so a config edit without an apache restart FAILS. The image CMD boots httpd
# (see .preserve-cmd); verify.sh must NOT start it - a dead server is a failure.
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "closed the vulnerability but killed httpd" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

HOST=127.0.0.1
PORT=443

if ! command -v openssl >/dev/null 2>&1; then
    record_reg tls12_handshake 0 "openssl missing - cannot probe the live server"
    record_poc legacy_tls_refused 0 "openssl missing - cannot run the TLS handshake probe"
    verify_finish
fi

# Returns 0 if a full TLS handshake at $1 protocol succeeds (cert received).
handshake() {  # $1 = openssl proto flag e.g. -tls1
    local out
    out=$(timeout 12 bash -c "echo | openssl s_client $1 -connect $HOST:$PORT 2>&1" 2>/dev/null)
    printf '%s' "$out" | grep -q 'BEGIN CERTIFICATE'
}

# --- Regression: is the server actually up and doing modern TLS? ---
if handshake "-tls1_2"; then
    record_reg tls12_handshake 1
else
    record_reg tls12_handshake 0 "no TLSv1.2 handshake on $HOST:$PORT - apache is down or broken"
fi

# --- PoC: deprecated protocols must be REFUSED by the live server ---
if handshake "-tls1"; then
    record_poc tls10_refused 0 "server negotiated TLSv1.0 - deprecated protocol still enabled (config may say TLSv1.2+, but was apache restarted?)"
else
    record_poc tls10_refused 1
fi

if handshake "-tls1_1"; then
    record_poc tls11_refused 0 "server negotiated TLSv1.1 - deprecated protocol still enabled"
else
    record_poc tls11_refused 1
fi

# --- PoC: weak ciphers (RC4/3DES) must not be offered over TLSv1.2 ---
WEAK_ACCEPTED=""
for weak in RC4-SHA DES-CBC3-SHA; do
    if timeout 12 bash -c "echo | openssl s_client -tls1_2 -cipher $weak -connect $HOST:$PORT 2>&1" 2>/dev/null | grep -q 'BEGIN CERTIFICATE'; then
        WEAK_ACCEPTED="$WEAK_ACCEPTED $weak"
    fi
done
if [ -n "$WEAK_ACCEPTED" ]; then
    record_poc weak_ciphers_refused 0 "live server accepted weak cipher(s):$WEAK_ACCEPTED"
else
    record_poc weak_ciphers_refused 1
fi

verify_finish
