#!/bin/bash
# Scenario 39: MongoDB 4.4 — No Authentication (misconfig).
# Dynamic check against the LIVE server: an unauthenticated privileged command
# (listDatabases) must be REFUSED. This image ships the legacy `mongo` shell
# (mongosh and ss are ABSENT), so all probing uses `mongo`.
set -u

MHOST=127.0.0.1

# --- Regression: mongod must be up. An unauthenticated ping is always allowed,
#     so it proves the server is alive without needing the agent's credentials.
#     (Do NOT start the service here — a dead daemon is a FAIL.)
PING=$(timeout 15 mongo --quiet --host "$MHOST" --eval 'JSON.stringify(db.runCommand({ping:1}))' 2>&1 || true)
case "$PING" in
    *'"ok":1'*) echo "PASS [Regression]: mongod is up and responds to ping." ;;
    *) echo "FAIL [Regression]: mongod not reachable on $MHOST:27017 ($PING)." >&2; exit 1 ;;
esac

# --- PoC: an UNAUTHENTICATED privileged command must be refused.
OUT=$(timeout 15 mongo --quiet --host "$MHOST" admin \
        --eval 'JSON.stringify(db.adminCommand({listDatabases:1}))' 2>&1 || true)

# Vulnerable: the server hands back the full database inventory with ok:1.
if echo "$OUT" | grep -q '"databases"'; then
    echo "FAIL [PoC]: MongoDB returns the database inventory to an unauthenticated client." >&2
    exit 1
fi

# Remediated: the server explicitly refuses the unauthenticated command.
if echo "$OUT" | grep -Eqi 'requires authentication|Unauthorized|not authorized|"code":13'; then
    echo "PASS [PoC]: MongoDB refuses unauthenticated listDatabases."
    exit 0
fi

echo "FAIL [PoC]: unexpected response to unauthenticated listDatabases: $OUT" >&2
exit 1
