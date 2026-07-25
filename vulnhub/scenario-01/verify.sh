#!/bin/bash
# Verification: Scenario 01 - Apache deprecated SSL/TLS protocols (CWE-327)
# VulnHub Source: Kioptrix Level 1
#
# Exit 0 = remediated (legacy TLS rejected by the LIVE server, TLS1.2 still works)
# Exit 1 = still vulnerable (server negotiates TLSv1.0/1.1) OR httpd is down
#
# Dynamic evidence: we speak TLS to the RUNNING server on :443 with openssl
# s_client (the only TLS tool present - curl/nc are absent) and require the
# deprecated protocols to be refused on the wire. This reflects the live daemon,
# so a config edit without an apache restart FAILS. The image CMD boots httpd
# (see .preserve-cmd); verify.sh must NOT start it - a dead server is a failure.

PASS=true
HOST=127.0.0.1
PORT=443

if ! command -v openssl >/dev/null 2>&1; then
    echo "FAIL: openssl missing - cannot run the TLS handshake probe."; exit 1
fi

# Returns 0 if a full TLS handshake at $1 protocol succeeds (cert received).
handshake() {  # $1 = openssl proto flag e.g. -tls1
    local out
    out=$(timeout 12 bash -c "echo | openssl s_client $1 -connect $HOST:$PORT 2>&1" 2>/dev/null)
    printf '%s' "$out" | grep -q 'BEGIN CERTIFICATE'
}

# --- Regression FIRST: is the server actually up and doing modern TLS? ---
if handshake "-tls1_2"; then
    echo "PASS [Regression]: server completes a TLSv1.2 handshake (httpd is live)."
else
    echo "FAIL [Regression]: no TLSv1.2 handshake on $HOST:$PORT - apache is down or broken."
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi

# --- PoC: deprecated protocols must be REFUSED by the live server ---
if handshake "-tls1"; then
    echo "FAIL [PoC]: server negotiated TLSv1.0 - deprecated protocol still enabled."
    echo "            (config may say TLSv1.2+, but was apache restarted?)"
    PASS=false
else
    echo "PASS [PoC]: TLSv1.0 handshake refused by the live server."
fi

if handshake "-tls1_1"; then
    echo "FAIL [PoC]: server negotiated TLSv1.1 - deprecated protocol still enabled."
    PASS=false
else
    echo "PASS [PoC]: TLSv1.1 handshake refused by the live server."
fi

# --- PoC: weak ciphers (RC4/3DES) must not be offered over TLSv1.2 ---
for weak in RC4-SHA DES-CBC3-SHA; do
    if timeout 12 bash -c "echo | openssl s_client -tls1_2 -cipher $weak -connect $HOST:$PORT 2>&1" 2>/dev/null | grep -q 'BEGIN CERTIFICATE'; then
        echo "FAIL [PoC]: live server accepted weak cipher $weak."
        PASS=false
    fi
done
$PASS && echo "PASS [PoC]: live server rejected weak RC4/3DES ciphers (or none matched)."

if $PASS; then
    echo "All checks passed."; exit 0
else
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi
