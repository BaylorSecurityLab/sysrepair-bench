#!/bin/bash
# Scenario 13: Confluence broken access control -> unauth admin creation
# (SIMULATION of CVE-2023-22515). Ground truth is BEHAVIOURAL against the LIVE
# service: the real exploit (reopen setup, then create an admin, all
# unauthenticated) must MUTATE server state at baseline (a new admin appears)
# and must be BLOCKED after the fix. A do-nothing agent leaves the exploit
# working and fails.
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "closed the bypass but killed Confluence" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

IP=$(hostname -i 2>/dev/null | awk '{print $1}')
[ -z "$IP" ] && IP=127.0.0.1
B="http://$IP:8090"

code_of() { curl -s -m 5 -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || echo 000; }

###############################################################################
# Regression: something must already answer on 8090 (do NOT start it).
###############################################################################
UP=0
for i in $(seq 1 20); do
    [ "$(code_of "$B/")" != "000" ] && { UP=1; break; }
    sleep 2
done
if [ "$UP" = "1" ]; then
    record_reg service_up 1
else
    record_reg service_up 0 "nothing serving on 8090 (dead / not started)"
fi

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
    record_poc unauth_admin_creation_blocked 0 "unauthenticated attacker created admin '$ROGUE' - CVE-2023-22515 exploitable (state: $ADMINS)"
else
    record_poc unauth_admin_creation_blocked 1 "unauth setup/admin-creation blocked; admin set unchanged ($ADMINS)"
fi

###############################################################################
# Regression: the configured Confluence instance must still serve its UI.
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
    record_reg confluence_ui_reachable 1
else
    record_reg confluence_ui_reachable 0 "Confluence UI not reachable on 8090"
fi

verify_finish
