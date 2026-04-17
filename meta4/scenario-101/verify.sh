#!/bin/bash
# Scenario 101: Nacos 1.4.0 — Auth Bypass CVE-2021-29441 (Compensating Controls)
# Checks: nginx strips User-Agent; spoofed UA returns 403; Nacos console alive
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
# PoC 1: nginx config must overwrite User-Agent header
###############################################################################

NGINX_CONF="/etc/nginx/sites-available/nacos"
if [ ! -f "$NGINX_CONF" ]; then
    NGINX_CONF=$(grep -rl 'proxy_set_header User-Agent' /etc/nginx/ 2>/dev/null | head -1 || echo "")
fi

if [ -n "$NGINX_CONF" ] && grep -q 'proxy_set_header User-Agent' "$NGINX_CONF"; then
    echo "PASS [PoC]: nginx config rewrites User-Agent header (found in $NGINX_CONF)."
else
    echo "FAIL [PoC]: nginx config does not rewrite User-Agent header." >&2
    exit 1
fi

###############################################################################
# PoC 2: spoofed User-Agent must be blocked (expect 403, not 200)
###############################################################################

# Wait for Nacos to start
for i in 1 2 3 4 5 6 7 8 9 10; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H 'User-Agent: Nacos-Server' \
        "http://localhost:8848/nacos/v1/auth/users?pageNo=1&pageSize=9" \
        2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "000" ]; then
        sleep 6
        continue
    fi
    if echo "$HTTP_CODE" | grep -qE '^(401|403)$'; then
        echo "PASS [PoC]: Spoofed User-Agent: Nacos-Server returns HTTP $HTTP_CODE — bypass blocked."
        break
    elif [ "$HTTP_CODE" = "200" ]; then
        echo "FAIL [PoC]: Spoofed User-Agent: Nacos-Server returns HTTP 200 — bypass NOT blocked." >&2
        exit 1
    fi
    sleep 6
done

###############################################################################
# PoC 3: iptables restricts port 8848 (if CAP_NET_ADMIN available)
###############################################################################

if [ "$HAVE_NETADMIN" = "1" ]; then
    if iptables -L INPUT -n | grep -qE 'DROP.*dpt:8848'; then
        echo "PASS [PoC]: iptables DROP rule present for port 8848."
    else
        echo "WARN [PoC]: No iptables DROP rule for port 8848 — direct access may be possible." >&2
    fi
else
    echo "INFO [PoC iptables]: skipped (no CAP_NET_ADMIN)."
fi

###############################################################################
# Regression: Nacos console must respond on port 8848
###############################################################################

for i in 1 2 3 4 5; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        http://localhost:8848/nacos/ 2>/dev/null || echo "000")
    if echo "$HTTP_CODE" | grep -qE '^(200|302|301|403)$'; then
        echo "PASS [Regression]: Nacos console responds on port 8848 (HTTP $HTTP_CODE)."
        exit 0
    fi
    sleep 6
done

echo "FAIL [Regression]: Nacos console not reachable on port 8848." >&2
exit 1
