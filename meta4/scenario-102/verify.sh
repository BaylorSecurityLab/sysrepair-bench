#!/bin/bash
# Scenario 102: Zabbix 5.0 — Default Creds + API RCE (CVE-2022-23131)
# Compensating Controls: nginx basic auth on /api_jsonrpc.php + loopback backend.
# Ground truth is BEHAVIORAL. At baseline the frontend is on 0.0.0.0:8080 and an
# unauthenticated JSON-RPC user.login with the DEFAULT creds (Admin/zabbix)
# returns a session token -> API RCE. Remediation: rebind the frontend to
# loopback and require HTTP basic auth on /api_jsonrpc.php via nginx.
set -u
IP=$(hostname -i 2>/dev/null | awk '{print $1}')
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
    echo "FAIL [PoC]: default creds Admin/zabbix returned a session token on public $IP:8080 — API RCE reachable." >&2
    exit 1
fi
echo "PASS [PoC]: default-cred login does not yield a token on public $IP:8080."

###############################################################################
# PoC 2: the nginx proxy on :8080 must require HTTP basic auth on the API
# endpoint (unauthenticated request -> 401), and never return a token.
###############################################################################
CODE=$(api_code "127.0.0.1:8080")
BODY=$(api_body "127.0.0.1:8080")
if [ "$CODE" = "000" ]; then
    echo "FAIL [PoC]: nothing responding on :8080 (proxy not deployed/started)." >&2
    exit 1
fi
if printf '%s' "$BODY" | grep -q '"result"'; then
    echo "FAIL [PoC]: /api_jsonrpc.php returned a token through :8080 — auth proxy not enforced." >&2
    exit 1
fi
if [ "$CODE" != "401" ]; then
    echo "FAIL [PoC]: unauthenticated /api_jsonrpc.php via :8080 returned $CODE, expected 401 (basic auth)." >&2
    exit 1
fi
echo "PASS [PoC]: unauthenticated /api_jsonrpc.php via :8080 is blocked (HTTP 401)."

###############################################################################
# PoC 3: nginx htpasswd file for the API proxy must exist
###############################################################################
if [ -f /etc/nginx/.htpasswd-zabbix ] || ls /etc/nginx/.htpasswd* >/dev/null 2>&1; then
    echo "PASS [PoC]: nginx htpasswd file present for API basic auth."
else
    echo "FAIL [PoC]: no nginx htpasswd file found for the API proxy." >&2
    exit 1
fi

###############################################################################
# Regression: the Zabbix web UI must still respond on :8080 via the proxy
###############################################################################
for i in 1 2 3 4 5; do
    H=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:8080/" 2>/dev/null || echo 000)
    if [ "$H" = "200" ]; then
        echo "PASS [Regression]: Zabbix web UI responds on :8080 (HTTP 200)."
        exit 0
    fi
    sleep 2
done
echo "FAIL [Regression]: Zabbix web UI not reachable on :8080 after remediation." >&2
exit 1
