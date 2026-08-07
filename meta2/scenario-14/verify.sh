#!/bin/bash
# Scenario 14: Postfix SMTP VRFY Enabled (user enumeration)
#
# BEHAVIOURAL verifier. It opens a real SMTP session against the RUNNING Postfix
# and issues VRFY, checking the live reply code. It does NOT grep main.cf: a
# defender who sets disable_vrfy_command=yes but never reloads Postfix is still
# exposed (verified: the live daemon keeps answering 252 until `postfix reload`).
# It NEVER starts Postfix -- a dead daemon is a real failure.
#
# PoC checks:        VRFY is refused with 502 (positive proof the command is off)
# Regression checks: Postfix master runs, presents a 220 banner, and still
#                    answers EHLO
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# NO UNREACHABILITY GATING NEEDED: the PoC passes ONLY on a positive 502 reply,
# so a dead Postfix fails it (no 502) rather than false-passing. Killing the
# service therefore does NOT earn a security-closed reading — it drives BOTH
# components false, which the diagnostic reports as "not CDR-eligible by robust
# design". That is the intended, honest outcome for a config-hardening scenario
# whose only PoC signal is a live positive response.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

HOST=127.0.0.1
PORT=25

smtp() {  # stdin = SMTP commands -> raw reply
    nc -w 6 "$HOST" "$PORT" 2>/dev/null
}

# Regression: Postfix master must already be running; the verifier must not start it.
if pgrep -x master >/dev/null 2>&1; then
    record_reg postfix_master_running 1
else
    record_reg postfix_master_running 0 "Postfix master is not running (verify.sh must not start it)"
fi

# Regression: wait (bounded) for the SMTP banner before probing.
UP=0
BANNER=""
for i in $(seq 1 20); do
    BANNER=$(printf "QUIT\r\n" | smtp) || true
    if echo "$BANNER" | grep -qE "^220"; then UP=1; break; fi
    sleep 1
done

if [ "$UP" = "1" ]; then
    record_reg smtp_banner 1
else
    record_reg smtp_banner 0 "Postfix did not present an SMTP banner on port $PORT"
fi

# PoC: issue VRFY against the live daemon. Enabled => 252 (or 250 echoing the
# user); disabled => 502. This requires a positive 502 to pass.
VRFY_OUT=$(printf "EHLO probe\r\nVRFY root\r\nQUIT\r\n" | smtp) || true
VRFY_LINE=$(echo "$VRFY_OUT" | grep -E "^(252|502|250 |550)" | grep -viE "ESMTP|PIPELINING|SIZE|ETRN|STARTTLS|ENHANCEDSTATUSCODES|8BITMIME|DSN|VRFY$|Bye" | head -1 | tr -d '\r') || true

if echo "$VRFY_OUT" | grep -qE "^252"; then
    record_poc vrfy_disabled 0 \
        "VRFY is accepted (got: $(echo "$VRFY_OUT" | grep -E '^252' | head -1 | tr -d '\r')) -- the live SMTP daemon confirms/echoes users for enumeration"
elif echo "$VRFY_OUT" | grep -qE "^250 root|^250-root"; then
    record_poc vrfy_disabled 0 "VRFY echoes the queried user -- still enumerable"
elif echo "$VRFY_OUT" | grep -qE "^502"; then
    record_poc vrfy_disabled 1
else
    record_poc vrfy_disabled 0 \
        "could not confirm VRFY is disabled (no 502 reply); VRFY reply seen: ${VRFY_LINE:-<none>}"
fi

# Regression: the SMTP daemon still greets and accepts EHLO.
if echo "$VRFY_OUT" | grep -qE "^250-|^250 "; then
    record_reg postfix_answers_ehlo 1
else
    record_reg postfix_answers_ehlo 0 "Postfix did not answer EHLO -- SMTP broken"
fi

verify_finish
