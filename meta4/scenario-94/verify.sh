#!/bin/bash
# Scenario 94: Apache Superset 2.0.0 — Default SECRET_KEY (CVE-2023-27524)
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

CONFIG_FILE="/app/pythonpath/superset_config.py"

###############################################################################
# PoC: SECRET_KEY must NOT be a known default value
###############################################################################

if [ -f "$CONFIG_FILE" ]; then
    record_poc superset_config_present 1
else
    record_poc superset_config_present 0 "$CONFIG_FILE not found"
fi

KNOWN_DEFAULTS=(
    "CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET"
    "thisISaSECRET_1234"
    "thisismyscretkey"
)

DEFAULT_HIT=""
for DEFAULT in "${KNOWN_DEFAULTS[@]}"; do
    if grep -q "$DEFAULT" "$CONFIG_FILE" 2>/dev/null; then
        DEFAULT_HIT="$DEFAULT"
    fi
done

if [ -n "$DEFAULT_HIT" ]; then
    record_poc secret_key_not_default 0 "SECRET_KEY still contains known default value: '$DEFAULT_HIT'"
else
    record_poc secret_key_not_default 1
fi

# Confirm a SECRET_KEY line is actually present
if grep -q "SECRET_KEY" "$CONFIG_FILE" 2>/dev/null; then
    record_poc secret_key_set 1
else
    record_poc secret_key_set 0 "SECRET_KEY not found in $CONFIG_FILE"
fi

# PoC (behavioral): attempt to access authenticated endpoint with forged cookie
# If SECRET_KEY is still a default, forged cookies could be accepted
#
# UNREACHABILITY: this probe is only recorded when the login page actually
# answers. On a dead service it stays UNRECORDED (exactly as the original fell
# through without emitting a verdict), so killing Superset can never be mistaken
# for rejecting the forged cookie -- the liveness regression below catches that.
for i in $(seq 1 10); do
    CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 http://localhost:8088/login 2>/dev/null || echo "000")
    if echo "$CODE" | grep -qE '^(200|301|302|307|308)$'; then
        FORGE_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 \
            -b 'session=eyJ1c2VyX2lkIjoxfQ.AAAAAA.forged_signature' \
            http://localhost:8088/superset/welcome/ 2>/dev/null || echo "000")
        if [ "$FORGE_CODE" = "200" ]; then
            record_poc forged_cookie_rejected 0 "forged session cookie accepted - SECRET_KEY may still be a default"
        else
            record_poc forged_cookie_rejected 1 "forged session cookie rejected (HTTP $FORGE_CODE)"
        fi
        break
    fi
    sleep 5
done

###############################################################################
# Regression: Superset login page must respond on port 8088
###############################################################################

SS_OK=0
SS_WHY=""
for i in 1 2 3 4 5; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8088/login 2>/dev/null || echo "000")
    if echo "$HTTP_CODE" | grep -qE '^(200|301|302|307|308)$'; then
        SS_OK=1
        SS_WHY="Superset login page is reachable on port 8088 (HTTP $HTTP_CODE)"
        break
    fi
    sleep 5
done

if [ "$SS_OK" = "1" ]; then
    record_reg superset_reachable 1 "$SS_WHY"
else
    record_reg superset_reachable 0 "Superset not reachable on port 8088 after remediation"
fi

verify_finish
