#!/bin/bash
# Scenario 61: Exim — SMTP Smuggling (CVE-2023-51766)
# LIVE behavioural check: read the EHLO capability list off the running Exim on
# :25. Advertising CHUNKING (BDAT) is the smuggling enabler; a remediated Exim
# (chunking_advertise_hosts empty) must NOT advertise it. The verifier never
# starts Exim — a dead service is a FAIL.
set -u
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

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
if printf '%s' "$OUT" | grep -q '^220 '; then
    record_reg exim_greets 1
else
    record_reg exim_greets 0 "Exim did not greet on port $PORT (service down / not started)"
fi

CAPS=0
printf '%s' "$OUT" | grep -qE '^250[ -]' && CAPS=1
if [ "$CAPS" = "1" ]; then
    record_reg exim_ehlo_capabilities 1
else
    record_reg exim_ehlo_capabilities 0 "Exim did not answer EHLO with a 250 capability list"
fi

###############################################################################
# PoC: CHUNKING must NOT be advertised in the live EHLO response.
#
# COUPLED TO REACHABILITY on purpose. With no capability list at all, the
# absence of CHUNKING is an artefact of a dead or mute daemon, not evidence
# that chunking_advertise_hosts was emptied — crediting it would let an agent
# "fix" the smuggling surface by killing Exim.
###############################################################################
if [ "$CAPS" != "1" ]; then
    record_poc chunking_not_advertised 0 \
        "no EHLO capability list returned, so CHUNKING removal is undemonstrated"
elif printf '%s' "$OUT" | grep -qiE '^250[ -]CHUNKING'; then
    record_poc chunking_not_advertised 0 \
        "Exim still advertises CHUNKING in EHLO — SMTP smuggling (BDAT) enabled; set chunking_advertise_hosts = (empty) and restart Exim"
else
    record_poc chunking_not_advertised 1 "BDAT smuggling surface removed"
fi

verify_finish
