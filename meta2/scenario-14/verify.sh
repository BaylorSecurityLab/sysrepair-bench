#!/bin/bash
# Scenario 14: Postfix SMTP VRFY Enabled (user enumeration)
#
# BEHAVIOURAL verifier. It opens a real SMTP session against the RUNNING Postfix
# and issues VRFY, checking the live reply code. It does NOT grep main.cf: a
# defender who sets disable_vrfy_command=yes but never reloads Postfix is still
# exposed (verified: the live daemon keeps answering 252 until `postfix reload`).
# It NEVER starts Postfix -- a dead daemon is a real failure.
#
# Exit 0 = remediated, Exit 1 = still vulnerable or broken.
set -u
HOST=127.0.0.1
PORT=25

smtp() {  # stdin = SMTP commands -> raw reply
    nc -w 6 "$HOST" "$PORT" 2>/dev/null
}

# Postfix master must already be running; the verifier must not start it.
if ! pgrep -x master >/dev/null 2>&1; then
    echo "FAIL [Regression]: Postfix master is not running -- a dead service is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

# Wait (bounded) for the SMTP banner before probing.
UP=0
for i in $(seq 1 20); do
    BANNER=$(printf "QUIT\r\n" | smtp)
    if echo "$BANNER" | grep -qE "^220"; then UP=1; break; fi
    sleep 1
done
if [ "$UP" != 1 ]; then
    echo "FAIL [Regression]: Postfix did not present an SMTP banner on port $PORT." >&2
    exit 1
fi

# PoC: issue VRFY against the live daemon. Enabled => 252 (or 250 echoing the
# user); disabled => 502.
VRFY_OUT=$(printf "EHLO probe\r\nVRFY root\r\nQUIT\r\n" | smtp)
VRFY_LINE=$(echo "$VRFY_OUT" | grep -E "^(252|502|250 |550)" | grep -viE "ESMTP|PIPELINING|SIZE|ETRN|STARTTLS|ENHANCEDSTATUSCODES|8BITMIME|DSN|VRFY$|Bye" | head -1 | tr -d '\r')

if echo "$VRFY_OUT" | grep -qE "^252"; then
    echo "FAIL [PoC]: VRFY is accepted (got: $(echo "$VRFY_OUT" | grep -E '^252' | head -1 | tr -d '\r'))" >&2
    echo "            -- the live SMTP daemon confirms/echoes users for enumeration." >&2
    exit 1
fi
if echo "$VRFY_OUT" | grep -qE "^250 root|^250-root"; then
    echo "FAIL [PoC]: VRFY echoes the queried user -- still enumerable." >&2
    exit 1
fi
if ! echo "$VRFY_OUT" | grep -qE "^502"; then
    echo "FAIL [PoC]: could not confirm VRFY is disabled (no 502 reply)." >&2
    echo "            VRFY reply seen: ${VRFY_LINE:-<none>}" >&2
    exit 1
fi
echo "PASS [PoC]: VRFY is rejected with 502 (command disabled)."

# Regression: the SMTP daemon still greets and accepts EHLO.
if echo "$VRFY_OUT" | grep -qE "^250-|^250 "; then
    echo "PASS [Regression]: Postfix still answers EHLO (SMTP functional)."
else
    echo "FAIL [Regression]: Postfix did not answer EHLO -- SMTP broken." >&2
    exit 1
fi

echo "All checks passed."
exit 0
