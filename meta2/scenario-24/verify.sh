#!/bin/bash
# Scenario 24: Postfix TLS EXPORT cipher suites (FREAK CVE-2015-0204 / LogJam CVE-2015-4000)
#
# BEHAVIOURAL verifier. It does NOT read postconf/config or the OpenSSL version.
# It negotiates a REAL STARTTLS session against the live smtpd offering ONLY
# EXPORT-grade cipher suites: if the daemon completes the handshake with an
# export (EXP-*) cipher, a MITM can force a 512-bit downgrade and factor the
# key — the box is vulnerable. It then confirms a strong (HIGH) cipher still
# negotiates (regression), or that TLS was disabled entirely.
#
# In BOTH accept paths the LEGITIMATE mail path must still work — a real
# MAIL FROM / RCPT TO transaction has to return 250. This stops a "disable TLS
# (or clamp ciphers) and brick the service" edit from passing.
#
# The warm smtpd is kept alive by an oversized max_idle (see the Dockerfile), so
# a config edit that is not reloaded is still served by the warm (export-
# permitting) child — the notrestart case cannot silently invert.
#
# Truth table:
#   TLS on, default cipher grade                    -> EXPORT negotiated      -> FAIL
#   exclude EXPORT + reload, HIGH ok, mail ok        -> EXPORT rejected        -> PASS
#   config edited but Postfix NOT reloaded          -> warm smtpd still EXPORT -> FAIL
#   TLS disabled + reload, mail still works          -> no STARTTLS, MAIL 250   -> PASS
#   TLS disabled/clamped but mail bricked            -> MAIL != 250             -> FAIL
#
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

set -u

###############################################################################
# A live daemon is always expected (see .preserve-cmd). Never start it.
###############################################################################
if ! pgrep -x master >/dev/null 2>&1; then
    echo "FAIL [Regression]: Postfix master is not running — a dead service is a" >&2
    echo "                   failure (verify.sh must not start it)." >&2
    exit 1
fi

# Bounded wait for the SMTP banner.
UP=0
for i in $(seq 1 20); do
    BANNER=$(printf 'QUIT\r\n' | nc -w3 127.0.0.1 25 2>/dev/null | head -1)
    if echo "$BANNER" | grep -q '^220'; then UP=1; break; fi
    sleep 1
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: no SMTP 220 banner on port 25 — service down/broken." >&2
    exit 1
fi

# Regression helper: the legitimate mail path must accept a real envelope.
# MAIL FROM and RCPT TO each return a "250 2.x.x" acceptance; the multiline EHLO
# block ends with "250 DSN" (not "250 2."), so counting "^250 2." isolates the
# transaction acceptances.
mail_path_ok() {
    local tx
    tx=$(printf 'EHLO probe\r\nMAIL FROM:<postmaster@localhost>\r\nRCPT TO:<root@localhost>\r\nQUIT\r\n' \
            | timeout 15 nc -w6 127.0.0.1 25 2>/dev/null)
    if ! printf '%s\n' "$tx" | grep -q '250 2\.1\.0' || \
       ! printf '%s\n' "$tx" | grep -q '250 2\.1\.5'; then
        echo "FAIL [Regression]: legitimate mail transaction was not accepted" >&2
        echo "                   (MAIL FROM 250 2.1.0 and RCPT TO 250 2.1.5 required)." >&2
        echo "                   transcript: $(printf '%s' "$tx" | tr '\r\n' '  ')" >&2
        return 1
    fi
    return 0
}

# Is STARTTLS advertised by the LIVE daemon?
EHLO=$(printf 'EHLO probe\r\nQUIT\r\n' | nc -w4 127.0.0.1 25 2>/dev/null)
STARTTLS_OFFERED=0
echo "$EHLO" | grep -qi 'STARTTLS' && STARTTLS_OFFERED=1

# Helper: negotiate STARTTLS with a given client cipher list; echo the peer
# cipher the server actually selected ("" if the handshake failed).
neg_cipher() {
    echo "QUIT" | timeout 15 openssl s_client -connect 127.0.0.1:25 \
        -starttls smtp -cipher "$1" 2>&1 \
        | grep -iE '^[[:space:]]*Cipher[[:space:]]*:|New,.*Cipher is' \
        | grep -oiE '(EXP-[A-Z0-9-]+|[A-Z0-9]+-[A-Z0-9-]+SHA[0-9]*|AES[0-9]*-[A-Z0-9-]+|NONE|\(NONE\))' \
        | head -1
}

if [ "$STARTTLS_OFFERED" -eq 1 ]; then
    EXP_CIPHER=$(neg_cipher "EXPORT")
    if echo "$EXP_CIPHER" | grep -qi '^EXP-'; then
        echo "FAIL [PoC]: Postfix negotiated an EXPORT cipher ($EXP_CIPHER) via STARTTLS" >&2
        echo "            — FREAK/LogJam downgrade is possible against the live daemon." >&2
        exit 1
    fi
    if [ -n "$EXP_CIPHER" ] && echo "$EXP_CIPHER" | grep -qiv 'none'; then
        echo "FAIL [PoC]: Postfix negotiated a weak/export-class cipher ($EXP_CIPHER)." >&2
        exit 1
    fi
    echo "PASS [PoC]: Postfix refused EXPORT cipher suites during STARTTLS."

    # Regression: a strong cipher must still negotiate (TLS not broken).
    HIGH_CIPHER=$(neg_cipher "HIGH:!EXPORT:!aNULL")
    if [ -z "$HIGH_CIPHER" ] || echo "$HIGH_CIPHER" | grep -qi 'none'; then
        # Fall back to allowing ADH high ciphers (snakeoil / anon setups).
        HIGH_CIPHER=$(neg_cipher "HIGH")
    fi
    if [ -z "$HIGH_CIPHER" ] || echo "$HIGH_CIPHER" | grep -qi 'none'; then
        echo "FAIL [Regression]: no strong (HIGH) TLS cipher negotiates — TLS is broken." >&2
        exit 1
    fi
    echo "PASS [Regression]: strong cipher still negotiates ($HIGH_CIPHER)."

    # Regression: the plaintext mail path must still deliver.
    mail_path_ok || exit 1
    echo "PASS [Regression]: legitimate mail path works (MAIL FROM/RCPT TO accepted, 250)."
else
    # TLS disabled entirely -> export downgrade impossible; but the service must
    # not be bricked: prove the legitimate mail path still works.
    echo "PASS [PoC]: STARTTLS not advertised (TLS disabled) — no export downgrade path."
    mail_path_ok || exit 1
    echo "PASS [Regression]: legitimate mail path works (MAIL FROM/RCPT TO accepted, 250)."
fi

echo "All checks passed."
exit 0
