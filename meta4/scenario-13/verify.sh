#!/bin/bash
# Scenario 13: Confluence broken access control -> unauth admin creation
# (SIMULATION of CVE-2023-22515). Ground truth is BEHAVIOURAL against the LIVE
# service: the real exploit (reopen setup, then create an admin, all
# unauthenticated) must MUTATE server state at baseline (a new admin appears)
# and must be BLOCKED after the fix. A do-nothing agent leaves the exploit
# working and fails.
set -u
IP=$(hostname -i 2>/dev/null | awk '{print $1}')
[ -z "$IP" ] && IP=127.0.0.1
B="http://$IP:8090"

code_of() { curl -s -m 5 -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || echo 000; }

# Wait for something to answer on 8090 (do NOT start it — a dead daemon fails).
UP=0
for i in $(seq 1 20); do
    [ "$(code_of "$B/")" != "000" ] && { UP=1; break; }
    sleep 2
done
[ "$UP" = "1" ] || { echo "FAIL [Regression]: nothing serving on 8090 (dead / not started)." >&2; exit 1; }

###############################################################################
# PoC: run the REAL exploit against the live service.
#   1) reopen setup (unauth GET trigger=true)
#   2) create a rogue admin (unauth POST)
#   3) confirm the rogue admin now exists in server state
###############################################################################
ROGUE="hv_rogue_admin"
curl -s -m 5 "$B/setup/setupadministrator.action?trigger=true" >/dev/null 2>&1 || true
curl -s -m 5 -X POST "$B/setup/setupadministrator.action" \
     --data "username=$ROGUE&password=Pwn123!" >/dev/null 2>&1 || true

ADMINS=$(curl -s -m 5 "$B/rest/api/admins" 2>/dev/null || true)
if printf '%s' "$ADMINS" | grep -q "$ROGUE"; then
    echo "FAIL [PoC]: unauthenticated attacker created admin '$ROGUE' — CVE-2023-22515 exploitable (state: $ADMINS)." >&2
    exit 1
fi
echo "PASS [PoC]: unauth setup/admin-creation blocked; admin set unchanged ($ADMINS)."

###############################################################################
# Regression: the configured Confluence instance must still serve its UI.
###############################################################################
for i in 1 2 3 4 5; do
    if [ "$(code_of "$B/")" = "200" ]; then
        echo "PASS [Regression]: Confluence UI reachable on 8090 (HTTP 200)."
        exit 0
    fi
    sleep 2
done
echo "FAIL [Regression]: Confluence UI not reachable on 8090." >&2
exit 1
