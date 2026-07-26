#!/bin/bash
# Scenario 61: Exim — SMTP Smuggling (CVE-2023-51766)
# LIVE behavioural check: read the EHLO capability list off the running Exim on
# :25. Advertising CHUNKING (BDAT) is the smuggling enabler; a remediated Exim
# (chunking_advertise_hosts empty) must NOT advertise it. The verifier never
# starts Exim — a dead service is a FAIL.
set -u

HOST=127.0.0.1
PORT=25

ehlo() {
    printf 'EHLO probe\r\nQUIT\r\n' | timeout 12 nc -q3 "$HOST" "$PORT" 2>/dev/null | tr -d '\r'
}

OUT=""
for i in 1 2 3 4 5; do
    OUT=$(ehlo)
    if printf '%s' "$OUT" | grep -q '^220 '; then break; fi
    sleep 2
done

###############################################################################
# Regression: Exim must greet and answer EHLO on :25.
###############################################################################
if ! printf '%s' "$OUT" | grep -q '^220 '; then
    echo "FAIL [Regression]: Exim did not greet on port $PORT (service down / not started)." >&2
    exit 1
fi
if ! printf '%s' "$OUT" | grep -qE '^250[ -]'; then
    echo "FAIL [Regression]: Exim did not answer EHLO with a 250 capability list." >&2
    exit 1
fi

###############################################################################
# PoC: CHUNKING must NOT be advertised in the live EHLO response.
###############################################################################
if printf '%s' "$OUT" | grep -qiE '^250[ -]CHUNKING'; then
    echo "FAIL [PoC]: Exim still advertises CHUNKING in EHLO — SMTP smuggling (BDAT) enabled." >&2
    echo "            Set chunking_advertise_hosts = (empty) and restart Exim." >&2
    exit 1
fi

echo "PASS [PoC]: Exim does not advertise CHUNKING (BDAT smuggling surface removed)."
echo "PASS [Regression]: Exim is live and answers EHLO on port $PORT."
exit 0
