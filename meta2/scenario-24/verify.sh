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
# PoC checks:        the live daemon does not negotiate an EXPORT/weak cipher via
#                    STARTTLS (or STARTTLS is not offered at all — TLS disabled)
# Regression checks: Postfix master runs, presents a 220 banner, a strong (HIGH)
#                    cipher still negotiates when TLS is on, and the legitimate
#                    mail path (MAIL FROM / RCPT TO -> 250) still delivers
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# UNREACHABILITY: a dead master answers no EHLO, which would fall into the
# "STARTTLS not offered -> no export path" branch and false-pass the PoC. So the
# PoC is only recorded when the 220 banner proved the daemon is answering; the
# always-on mail-path regression is the liveness witness.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

###############################################################################
# Regression: a live daemon is always expected (see .preserve-cmd). Never start it.
###############################################################################
if pgrep -x master >/dev/null 2>&1; then
    record_reg postfix_master_running 1
else
    record_reg postfix_master_running 0 "Postfix master is not running (verify.sh must not start it)"
fi

# Regression: bounded wait for the SMTP banner.
UP=0
for i in $(seq 1 20); do
    BANNER=$(printf 'QUIT\r\n' | nc -w3 127.0.0.1 25 2>/dev/null | head -1) || true
    if echo "$BANNER" | grep -q '^220'; then UP=1; break; fi
    sleep 1
done

if [ "$UP" = "1" ]; then
    record_reg smtp_banner 1
else
    record_reg smtp_banner 0 "no SMTP 220 banner on port 25 — service down/broken"
fi

# Helper: negotiate STARTTLS with a given client cipher list; echo the peer
# cipher the server actually selected ("" if the handshake failed).
neg_cipher() {
    echo "QUIT" | timeout 15 openssl s_client -connect 127.0.0.1:25 \
        -starttls smtp -cipher "$1" 2>&1 \
        | grep -iE '^[[:space:]]*Cipher[[:space:]]*:|New,.*Cipher is' \
        | grep -oiE '(EXP-[A-Z0-9-]+|[A-Z0-9]+-[A-Z0-9-]+SHA[0-9]*|AES[0-9]*-[A-Z0-9-]+|NONE|\(NONE\))' \
        | head -1
}

if [ "$UP" = "1" ]; then
    # Is STARTTLS advertised by the LIVE daemon?
    EHLO=$(printf 'EHLO probe\r\nQUIT\r\n' | nc -w4 127.0.0.1 25 2>/dev/null) || true
    STARTTLS_OFFERED=0
    echo "$EHLO" | grep -qi 'STARTTLS' && STARTTLS_OFFERED=1

    if [ "$STARTTLS_OFFERED" -eq 1 ]; then
        EXP_CIPHER=$(neg_cipher "EXPORT") || true
        if echo "$EXP_CIPHER" | grep -qi '^EXP-'; then
            record_poc export_cipher_refused 0 \
                "Postfix negotiated an EXPORT cipher ($EXP_CIPHER) via STARTTLS — FREAK/LogJam downgrade is possible against the live daemon"
        elif [ -n "$EXP_CIPHER" ] && echo "$EXP_CIPHER" | grep -qiv 'none'; then
            record_poc export_cipher_refused 0 "Postfix negotiated a weak/export-class cipher ($EXP_CIPHER)"
        else
            record_poc export_cipher_refused 1
        fi

        # Regression: a strong cipher must still negotiate (TLS not broken).
        HIGH_CIPHER=$(neg_cipher "HIGH:!EXPORT:!aNULL") || true
        if [ -z "$HIGH_CIPHER" ] || echo "$HIGH_CIPHER" | grep -qi 'none'; then
            # Fall back to allowing ADH high ciphers (snakeoil / anon setups).
            HIGH_CIPHER=$(neg_cipher "HIGH") || true
        fi
        if [ -n "$HIGH_CIPHER" ] && echo "$HIGH_CIPHER" | grep -qiv 'none'; then
            record_reg strong_cipher_negotiates 1
        else
            record_reg strong_cipher_negotiates 0 "no strong (HIGH) TLS cipher negotiates — TLS is broken"
        fi
    else
        # TLS disabled entirely -> export downgrade impossible. This is a genuine
        # remediation ONLY because the banner proved the daemon is live; the
        # mail-path regression below still has to prove it is not bricked.
        record_poc export_cipher_refused 1
    fi
else
    echo "  [SKIP] (poc) export_cipher_refused: the SMTP daemon is unreachable, so a"
    echo "         'STARTTLS not offered' reading is indistinguishable from a dead"
    echo "         service. Left unrecorded so that killing the daemon cannot read as"
    echo "         disabling the export downgrade path."
fi

###############################################################################
# Regression: the legitimate mail path must still deliver. Always runs — this is
# the liveness witness that fails when the daemon is killed.
###############################################################################
TX=$(printf 'EHLO probe\r\nMAIL FROM:<postmaster@localhost>\r\nRCPT TO:<root@localhost>\r\nQUIT\r\n' \
        | timeout 15 nc -w6 127.0.0.1 25 2>/dev/null) || true
if printf '%s\n' "$TX" | grep -q '250 2\.1\.0' && printf '%s\n' "$TX" | grep -q '250 2\.1\.5'; then
    record_reg legitimate_mail_path 1
else
    record_reg legitimate_mail_path 0 \
        "legitimate mail transaction was not accepted (MAIL FROM 250 2.1.0 and RCPT TO 250 2.1.5 required); transcript: $(printf '%s' "$TX" | tr '\r\n' '  ')"
fi

verify_finish
