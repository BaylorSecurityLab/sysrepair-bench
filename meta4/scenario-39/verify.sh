#!/bin/bash
# Scenario 39: MongoDB 4.4 — No Authentication (misconfig).
# Dynamic check against the LIVE server: an unauthenticated privileged command
# (listDatabases) must be REFUSED. This image ships the legacy `mongo` shell
# (mongosh and ss are ABSENT), so all probing uses `mongo`.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "enabled auth but killed mongod" is reported as
# security_pass / regression_pass rather than a bare exit 1. See lib/verifylib.sh.
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

MHOST=127.0.0.1

# --- Regression: mongod must be up. An unauthenticated ping is always allowed,
#     so it proves the server is alive without needing the agent's credentials.
#     (Do NOT start the service here — a dead daemon is a FAIL.)
PING=$(timeout 15 mongo --quiet --host "$MHOST" --eval 'JSON.stringify(db.runCommand({ping:1}))' 2>&1 || true)
ALIVE=0
case "$PING" in
    *'"ok":1'*) ALIVE=1; record_reg mongod_responds_to_ping 1 ;;
    *)          record_reg mongod_responds_to_ping 0 "mongod not reachable on $MHOST:27017 ($PING)" ;;
esac

if [ "$ALIVE" = "1" ]; then
    ###########################################################################
    # PoC: an UNAUTHENTICATED privileged command must be refused.
    ###########################################################################
    OUT=$(timeout 15 mongo --quiet --host "$MHOST" admin \
            --eval 'JSON.stringify(db.adminCommand({listDatabases:1}))' 2>&1 || true)

    if echo "$OUT" | grep -q '"databases"'; then
        # Vulnerable: the server hands back the full database inventory with ok:1.
        record_poc unauth_listdatabases_refused 0 \
            "MongoDB returns the database inventory to an unauthenticated client"
    elif echo "$OUT" | grep -Eqi 'requires authentication|Unauthorized|not authorized|"code":13'; then
        # Remediated: the server explicitly refuses the unauthenticated command.
        record_poc unauth_listdatabases_refused 1
    else
        record_poc unauth_listdatabases_refused 0 \
            "unexpected response to unauthenticated listDatabases: $OUT"
    fi
else
    # mongod never answered a ping, so a failed listDatabases proves nothing
    # about authentication. Recorded as FAILED, never credited: a dead daemon
    # refuses every command, and that must not read as "auth is enforced". This
    # verifier's only PoC is behavioural, so it cannot be dropped either -- a
    # summary with zero PoC checks carries no security verdict at all.
    record_poc unauth_listdatabases_refused 0 \
        "not demonstrable: mongod unreachable, so a failed listDatabases proves nothing"
fi

verify_finish
