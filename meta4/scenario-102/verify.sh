#!/bin/bash
# Scenario 102: Zabbix 5.0 — Default Creds + API RCE (CVE-2022-23131)
# Compensating Controls: nginx auth on /api_jsonrpc.php + iptables
set -u

###############################################################################
# Pre-check: CAP_NET_ADMIN for iptables
###############################################################################

if iptables -L INPUT -n 2>/dev/null | grep -q 'Chain INPUT'; then
    HAVE_NETADMIN=1
else
    HAVE_NETADMIN=0
fi

###############################################################################
# PoC 1: unauthenticated POST to /api_jsonrpc.php must be blocked (401/403)
###############################################################################

for i in 1 2 3 4 5 6; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST http://localhost:8080/api_jsonrpc.php \
        -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","method":"user.login","params":{"user":"Admin","password":"zabbix"},"id":1}' \
        2>/dev/null || echo "000")
    if echo "$HTTP_CODE" | grep -qE '^(401|403)$'; then
        echo "PASS [PoC]: Unauthenticated /api_jsonrpc.php returns HTTP $HTTP_CODE — blocked by nginx."
        break
    elif [ "$HTTP_CODE" = "200" ]; then
        echo "FAIL [PoC]: /api_jsonrpc.php returns HTTP 200 without proxy auth — default creds exploitable." >&2
        exit 1
    elif [ "$HTTP_CODE" = "000" ]; then
        sleep 5
        continue
    fi
    sleep 5
done

###############################################################################
# PoC 2: nginx htpasswd file must exist (non-default API credentials)
###############################################################################

HTPASSWD="/etc/nginx/.htpasswd-zabbix"
if [ -f "$HTPASSWD" ]; then
    echo "PASS [PoC]: nginx htpasswd file exists at $HTPASSWD."
else
    echo "FAIL [PoC]: nginx htpasswd file not found at $HTPASSWD." >&2
    exit 1
fi

###############################################################################
# PoC 3: iptables restricts frontend port (if CAP_NET_ADMIN available)
###############################################################################

if [ "$HAVE_NETADMIN" = "1" ]; then
    if iptables -L INPUT -n | grep -qE 'DROP.*dpt:(80|8080)'; then
        echo "PASS [PoC]: iptables DROP rule present for frontend port."
    else
        echo "WARN [PoC]: No iptables DROP rule for frontend port 80/8080." >&2
    fi
else
    echo "INFO [PoC iptables]: skipped (no CAP_NET_ADMIN)."
fi

###############################################################################
# Regression: Zabbix web UI must respond on port 8080
###############################################################################

for i in 1 2 3 4 5; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        http://localhost:8080/ 2>/dev/null || echo "000")
    if echo "$HTTP_CODE" | grep -qE '^(200|302|301|401|403)$'; then
        echo "PASS [Regression]: Zabbix web UI responds on port 8080 (HTTP $HTTP_CODE)."
        exit 0
    fi
    sleep 5
done

echo "FAIL [Regression]: Zabbix web UI not reachable on port 8080 after remediation." >&2
exit 1
