#!/bin/bash
# Scenario 106: Apache APISIX Default Admin Token (CVE-2020-13945)
# Ground truth is BEHAVIORAL against the LIVE admin API on port 9080. The daemon
# boots already-running with the default key (.preserve-cmd); a key change that
# was never followed by a restart still serves the default key and FAILs here.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

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
#
# The admin API on 9080 boots already-running, so a silent 9080 is a destroyed
# service. The original already labelled this Regression, which is correct under
# the unreachability rule; it now records instead of aborting so the PoC below
# still runs.
if [ "$UP" = "1" ]; then
    record_reg admin_api_up 1 "APISIX admin API is up on 9080"
else
    record_reg admin_api_up 0 "APISIX admin API not responding on 9080 (dead/not restarted)"
fi

###############################################################################
# PoC: the well-known DEFAULT admin key must be REJECTED (not 200)
###############################################################################
STATUS=$(code_for_key "$DEFAULT_KEY")
if [ "$STATUS" = "200" ]; then
    record_poc default_key_rejected 0 "admin API accepted the default key $DEFAULT_KEY - RCE via default token"
else
    record_poc default_key_rejected 1 "default admin key rejected (HTTP $STATUS)"
fi

###############################################################################
# PoC 2 / Regression: the NEW configured key must actually work, proving the
# running service reloaded a non-default key (not merely that it is down).
###############################################################################
if [ -f /opt/apisix/admin.key ]; then
    NEWKEY=$(tr -d ' \t\r\n' < /opt/apisix/admin.key || true)
    if [ -n "$NEWKEY" ]; then
        if [ "$NEWKEY" = "$DEFAULT_KEY" ]; then
            record_poc admin_key_not_default 0 "admin.key still holds the default value"
        else
            record_poc admin_key_not_default 1
            NS=$(code_for_key "$NEWKEY")
            if [ "$NS" = "200" ]; then
                record_reg new_key_accepted 1 "running service accepts the new non-default admin key (HTTP 200)"
            else
                record_reg new_key_accepted 0 "the configured non-default key was rejected (HTTP $NS) - service not reloaded"
            fi
        fi
    fi
fi

verify_finish
