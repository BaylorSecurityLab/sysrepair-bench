#!/bin/bash
# Scenario 106: Apache APISIX Default Admin Token (CVE-2020-13945)
# Ground truth is BEHAVIORAL against the LIVE admin API on port 9080. The daemon
# boots already-running with the default key (.preserve-cmd); a key change that
# was never followed by a restart still serves the default key and FAILs here.
set -u
BASE=http://localhost:9080
DEFAULT_KEY=edd1c9f034335f136f87ad84b625c8f1

code_for_key() { # $1=key -> HTTP status against admin API
    curl -s -o /dev/null -w "%{http_code}" \
        -H "X-API-KEY: $1" "$BASE/apisix/admin/routes" 2>/dev/null || echo 000
}

# Wait for the live service (do NOT start it).
UP=0
for i in $(seq 1 15); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/healthz" 2>/dev/null)" = "200" ] && { UP=1; break; }
    sleep 2
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: APISIX admin API not responding on 9080 (dead/not restarted)." >&2
    exit 1
fi

###############################################################################
# PoC: the well-known DEFAULT admin key must be REJECTED (not 200)
###############################################################################
STATUS=$(code_for_key "$DEFAULT_KEY")
if [ "$STATUS" = "200" ]; then
    echo "FAIL [PoC]: admin API accepted the default key $DEFAULT_KEY — RCE via default token." >&2
    exit 1
fi
echo "PASS [PoC]: default admin key rejected (HTTP $STATUS)."

###############################################################################
# PoC 2 / Regression: the NEW configured key must actually work, proving the
# running service reloaded a non-default key (not merely that it is down).
###############################################################################
if [ -f /opt/apisix/admin.key ]; then
    NEWKEY=$(tr -d ' \t\r\n' < /opt/apisix/admin.key)
    if [ -n "$NEWKEY" ]; then
        if [ "$NEWKEY" = "$DEFAULT_KEY" ]; then
            echo "FAIL [PoC]: admin.key still holds the default value." >&2
            exit 1
        fi
        NS=$(code_for_key "$NEWKEY")
        if [ "$NS" != "200" ]; then
            echo "FAIL [Regression]: the configured non-default key was rejected (HTTP $NS) — service not reloaded." >&2
            exit 1
        fi
        echo "PASS [Regression]: running service accepts the new non-default admin key (HTTP 200)."
    fi
fi

echo "PASS [Regression]: APISIX admin API is up on 9080."
exit 0
