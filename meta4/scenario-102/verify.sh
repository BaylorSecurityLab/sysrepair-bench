#!/bin/bash
# Scenario 102: Zabbix 5.0 — Default Creds + API RCE (CVE-2022-23131)
# Compensating Controls: nginx basic auth on /api_jsonrpc.php + loopback backend.
# Ground truth is BEHAVIORAL. At baseline the frontend is on 0.0.0.0:8080 and an
# unauthenticated JSON-RPC user.login with the DEFAULT creds (Admin/zabbix)
# returns a session token -> API RCE. Remediation: rebind the frontend to
# loopback and require HTTP basic auth on /api_jsonrpc.php via nginx.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

IP=$(hostname -i 2>/dev/null | awk '{print $1}' || true)
[ -z "$IP" ] && IP=127.0.0.1
LOGIN='{"jsonrpc":"2.0","method":"user.login","params":{"user":"Admin","password":"zabbix"},"id":1}'

api_body() { # $1=host:port
    curl -s -m 6 -X POST "http://$1/api_jsonrpc.php" \
        -H 'Content-Type: application/json' -d "$LOGIN" 2>/dev/null || true
}
api_code() { # $1=host:port
    curl -s -m 6 -o /dev/null -w '%{http_code}' -X POST "http://$1/api_jsonrpc.php" \
        -H 'Content-Type: application/json' -d "$LOGIN" 2>/dev/null || echo 000
}

###############################################################################
# PoC 1: default-cred login must NOT yield a session token on the public API
###############################################################################
OUT=$(api_body "$IP:8080")
if printf '%s' "$OUT" | grep -q '"result"'; then
    record_poc default_creds_no_token_public 0 "default creds Admin/zabbix returned a session token on public $IP:8080 - API RCE reachable"
else
    record_poc default_creds_no_token_public 1 "default-cred login does not yield a token on public $IP:8080"
fi

###############################################################################
# PoC 2: the nginx proxy on :8080 must require HTTP basic auth on the API
# endpoint (unauthenticated request -> 401), and never return a token.
#
# RECLASSIFIED poc -> regression (UNREACHABILITY RULE). The original charged
# "nothing responding on :8080" to the PoC. Port 8080 IS the pre-existing Zabbix
# frontend on the untouched box, so a silent 8080 is a destroyed service, not a
# closed vulnerability -- it is recorded as a REGRESSION failure and no PoC
# verdict is emitted for the same condition. Condition, strictness and the exit-0
# state set are unchanged.
###############################################################################
CODE=$(api_code "127.0.0.1:8080")
BODY=$(api_body "127.0.0.1:8080")
if [ "$CODE" != "000" ]; then
    record_reg api_endpoint_responding 1
else
    record_reg api_endpoint_responding 0 "nothing responding on :8080 (frontend/proxy down)"
fi

if printf '%s' "$BODY" | grep -q '"result"'; then
    record_poc api_no_token_via_proxy 0 "/api_jsonrpc.php returned a token through :8080 - auth proxy not enforced"
else
    record_poc api_no_token_via_proxy 1
fi

if [ "$CODE" = "401" ]; then
    record_poc api_requires_basic_auth 1 "unauthenticated /api_jsonrpc.php via :8080 is blocked (HTTP 401)"
else
    record_poc api_requires_basic_auth 0 "unauthenticated /api_jsonrpc.php via :8080 returned $CODE, expected 401 (basic auth)"
fi

###############################################################################
# PoC 3: nginx htpasswd file for the API proxy must exist
###############################################################################
if [ -f /etc/nginx/.htpasswd-zabbix ] || ls /etc/nginx/.htpasswd* >/dev/null 2>&1; then
    record_poc htpasswd_present 1
else
    record_poc htpasswd_present 0 "no nginx htpasswd file found for the API proxy"
fi

###############################################################################
# Regression: the Zabbix web UI must still respond on :8080 via the proxy
###############################################################################
UI_OK=0
for i in 1 2 3 4 5; do
    H=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:8080/" 2>/dev/null || echo 000)
    if [ "$H" = "200" ]; then
        UI_OK=1
        break
    fi
    sleep 2
done

if [ "$UI_OK" = "1" ]; then
    record_reg zabbix_ui_responds 1 "Zabbix web UI responds on :8080 (HTTP 200)"
else
    record_reg zabbix_ui_responds 0 "Zabbix web UI not reachable on :8080 after remediation"
fi

verify_finish
