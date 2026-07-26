#!/bin/bash
# Scenario 60: Postfix — SMTP Smuggling (CVE-2023-51764)
# LIVE exploit: a single SMTP transaction whose DATA is terminated by a BARE
# "<LF>.<LF>" instead of "<CR><LF>.<CR><LF>". A vulnerable Postfix treats the
# bare terminator as end-of-data and accepts the SMUGGLED second message that
# follows, so TWO messages queue from one payload. A remediated Postfix
# (smtpd_forbid_bare_newline=yes, exclusions emptied) queues only ONE.
# The verifier never starts Postfix — a dead service is a FAIL. It cleans up any
# queued test mail so it leaves the mail system as it found it.
set -u

HOST=127.0.0.1
PORT=25

# Best-effort cleanup of the test messages this probe queues (leave the queue as
# we found it). postsuper -d ALL removes queue entries only.
cleanup() { postsuper -d ALL >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

# One SMTP session: message #1 ends with a BARE-LF dot; a smuggled message #2
# follows. Count "queued as" acknowledgements in the reply stream.
smuggle() {
    printf 'EHLO probe\r\nMAIL FROM:<a@localhost>\r\nRCPT TO:<root@localhost>\r\nDATA\r\nSubject: one\r\n\r\nbody\r\n.\nMAIL FROM:<smuggled@localhost>\r\nRCPT TO:<root@localhost>\r\nDATA\r\nSubject: two\r\n\r\nsmuggled\r\n.\r\nQUIT\r\n' \
        | timeout 15 nc -q3 "$HOST" "$PORT" 2>/dev/null
}

OUT=""
for i in 1 2 3 4 5; do
    OUT=$(smuggle)
    if printf '%s' "$OUT" | grep -q '^220 '; then break; fi
    sleep 2
done

if ! printf '%s' "$OUT" | grep -q '^220 '; then
    echo "FAIL [Regression]: Postfix did not greet on port $PORT (service down / not started)." >&2
    exit 1
fi

QUEUED=$(printf '%s' "$OUT" | grep -c 'Ok: queued as')

if [ "$QUEUED" -ge 2 ]; then
    echo "FAIL [PoC]: SMTP smuggling succeeded — one bare-LF payload queued $QUEUED messages." >&2
    echo "            Set smtpd_forbid_bare_newline=yes and empty the exclusions, then reload." >&2
    exit 1
fi

if [ "$QUEUED" -lt 1 ]; then
    echo "FAIL [Regression]: Postfix accepted no message from loopback (over-blocked / broken)." >&2
    exit 1
fi

echo "PASS [PoC]: bare-LF smuggling blocked — the payload queued only $QUEUED message."
echo "PASS [Regression]: Postfix is live on port $PORT and accepts legitimate mail."
exit 0
