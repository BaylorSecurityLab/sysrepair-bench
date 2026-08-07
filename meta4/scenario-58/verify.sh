#!/bin/bash
# Scenario 58: PowerDNS Auth - Weak/Default API Key (misconfig)
#
# BEHAVIOURAL: drives the live REST API on :8081. The vulnerability is a weak,
# well-known api-key ("powerdns") - an attacker who guesses it gets full DNS
# admin. The fix is to rotate to a strong random key AND restart the server.
#
# NOTE on the false "empty api-key" premise: on this PowerDNS version an empty
# api-key does NOT open the API (every request gets 401). So an empty-key config
# is NOT vulnerable; the honest, reproducible misconfig is a weak key, which is
# what this scenario seeds and what the PoC below exercises.
#
# The image CMD boots pdns_server (see .preserve-cmd), so a live server is
# ALWAYS expected; verify.sh must NEVER start it - a dead server, or a config
# edited-but-not-restarted, is a FAIL.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "rotated the key but killed pdns_server" is reported as
# security_pass / regression_pass rather than a bare exit 1. See lib/verifylib.sh.
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

CONF=/etc/powerdns/pdns.conf
WEAK_KEY="powerdns"   # the seeded weak/default key an attacker would try

###############################################################################
# Regression: the server must already be running (dead service = FAIL, do not
# start it). procps/pgrep is absent on debian-slim, so scan /proc portably.
###############################################################################
pdns_running() {
    for p in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
        [ "$(cat /proc/$p/comm 2>/dev/null)" = "pdns_server" ] && return 0
    done
    return 1
}
if pdns_running; then
    record_reg pdns_server_running 1
else
    record_reg pdns_server_running 0 \
        "pdns_server is not running - a dead server is a failure (verify.sh must not start it)"
fi

http_code() {  # $1 = extra curl args (may be empty)
    # No `|| echo 000`: curl already PRINTS 000 via -w on a failed connect, so an
    # added fallback would make CODE the two-line string "000\n000" and every
    # `= "000"` test below would miss, crediting a dead server.
    curl -s -o /dev/null -w '%{http_code}' $1 http://localhost:8081/api/v1/servers 2>/dev/null
}

###############################################################################
# PoC (primary, behavioural): the weak/default key must be REJECTED by the live
# API. At baseline it returns 200 (attacker is in); after remediation the key is
# rotated so it returns 401/403.
#
# A never-answering API is an UNREACHABLE service, not a rotated key: it is
# recorded as regression damage with the behavioural PoC left UNRECORDED, so
# killing pdns_server can never read as having closed the weak-key hole.
###############################################################################
CODE=""
for i in 1 2 3 4 5 6 7 8 9 10; do
    CODE=$(http_code "-H X-API-Key:${WEAK_KEY}")
    [ "$CODE" = "000" ] && { sleep 2; continue; }
    break
done
if [ "$CODE" = "000" ]; then
    record_reg pdns_api_answers 0 "the REST API on 8081 did not respond after retries"
    echo "  [SKIP] (poc) weak_api_key_rejected: API unreachable"
else
    record_reg pdns_api_answers 1
    if [ "$CODE" = "200" ]; then
        record_poc weak_api_key_rejected 0 \
            "the weak default API key '${WEAK_KEY}' is still accepted (HTTP 200)"
    else
        record_poc weak_api_key_rejected 1 "weak default API key rejected (HTTP $CODE)"
    fi
fi

###############################################################################
# Config check: api-key must be non-empty AND not the weak default.
###############################################################################
KEY_LINE=$(grep -E '^api-key=' "$CONF" 2>/dev/null | tail -1 || true)
API_KEY=$(printf '%s' "$KEY_LINE" | cut -d= -f2-)
if [ -z "$API_KEY" ]; then
    record_poc api_key_hardened 0 "pdns.conf has an empty/missing api-key"
elif [ "$API_KEY" = "$WEAK_KEY" ]; then
    record_poc api_key_hardened 0 "pdns.conf still uses the weak default api-key"
else
    record_poc api_key_hardened 1 "api-key is set to a non-default value in pdns.conf"
fi

###############################################################################
# Regression: unauthenticated access is refused, and the CURRENT key works.
###############################################################################
UNAUTH=$(http_code "")
if [ "$UNAUTH" = "200" ]; then
    record_reg unauthenticated_api_refused 0 "API served an unauthenticated request (HTTP 200)"
else
    record_reg unauthenticated_api_refused 1 "HTTP $UNAUTH"
fi

CUR_OK=0
CODE=""
if [ -n "$API_KEY" ]; then
    for i in 1 2 3 4 5; do
        CODE=$(http_code "-H X-API-Key:${API_KEY}")
        if [ "$CODE" = "200" ]; then
            CUR_OK=1
            break
        fi
        sleep 2
    done
fi
if [ "$CUR_OK" = "1" ]; then
    record_reg current_api_key_works 1 "API returns 200 with the current X-API-Key"
else
    record_reg current_api_key_works 0 \
        "API did not return 200 with the current key (last ${CODE:-no-key-configured})"
fi

verify_finish
