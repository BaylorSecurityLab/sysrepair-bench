#!/bin/bash
# Scenario 58: PowerDNS Auth - Weak/Default API Key (misconfig)
# Exit 0 = remediated (PASS); Exit 1 = still vulnerable or service broken (FAIL).
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
set -u

CONF=/etc/powerdns/pdns.conf
WEAK_KEY="powerdns"   # the seeded weak/default key an attacker would try

###############################################################################
# The server must already be running (dead service = FAIL, do not start it).
# procps/pgrep is absent on debian-slim, so scan /proc portably.
###############################################################################
pdns_running() {
    for p in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
        [ "$(cat /proc/$p/comm 2>/dev/null)" = "pdns_server" ] && return 0
    done
    return 1
}
if ! pdns_running; then
    echo "FAIL [Regression]: pdns_server is not running - a dead server is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

http_code() {  # $1 = extra curl args (may be empty)
    curl -s -o /dev/null -w '%{http_code}' $1 http://localhost:8081/api/v1/servers 2>/dev/null
}

###############################################################################
# PoC (primary, behavioural): the weak/default key must be REJECTED by the live
# API. At baseline it returns 200 (attacker is in); after remediation the key is
# rotated so it returns 401/403.
###############################################################################
CODE=""
for i in 1 2 3 4 5 6 7 8 9 10; do
    CODE=$(http_code "-H X-API-Key:${WEAK_KEY}")
    [ "$CODE" = "000" ] && { sleep 2; continue; }
    break
done
if [ "$CODE" = "200" ]; then
    echo "FAIL [PoC]: the weak default API key '${WEAK_KEY}' is still accepted (HTTP 200)." >&2
    exit 1
elif [ "$CODE" = "000" ]; then
    echo "FAIL [PoC]: API did not respond after retries." >&2
    exit 1
fi
echo "PASS [PoC]: weak default API key rejected (HTTP $CODE)."

###############################################################################
# Config check: api-key must be non-empty AND not the weak default.
###############################################################################
KEY_LINE=$(grep -E '^api-key=' "$CONF" 2>/dev/null | tail -1)
API_KEY=$(printf '%s' "$KEY_LINE" | cut -d= -f2-)
if [ -z "$API_KEY" ]; then
    echo "FAIL [PoC]: pdns.conf has an empty/missing api-key." >&2
    exit 1
fi
if [ "$API_KEY" = "$WEAK_KEY" ]; then
    echo "FAIL [PoC]: pdns.conf still uses the weak default api-key." >&2
    exit 1
fi
echo "PASS [PoC]: api-key is set to a non-default value in pdns.conf."

###############################################################################
# Regression: unauthenticated access is refused, and the CURRENT key works.
###############################################################################
UNAUTH=$(http_code "")
if [ "$UNAUTH" = "200" ]; then
    echo "FAIL [Regression]: API served an unauthenticated request (HTTP 200)." >&2
    exit 1
fi

for i in 1 2 3 4 5; do
    CODE=$(http_code "-H X-API-Key:${API_KEY}")
    if [ "$CODE" = "200" ]; then
        echo "PASS [Regression]: API returns 200 with the current X-API-Key; unauth refused ($UNAUTH)."
        exit 0
    fi
    sleep 2
done

echo "FAIL [Regression]: API did not return 200 with the current key after remediation (last $CODE)." >&2
exit 1
