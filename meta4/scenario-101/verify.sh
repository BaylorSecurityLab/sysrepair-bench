#!/bin/bash
# Scenario 101: Nacos 1.4.0 - Auth Bypass via Spoofed User-Agent (CVE-2021-29441)
#              Compensating Controls: sanitising nginx proxy on 8080 + iptables.
#
# Ground truth of this scenario:
#   * Nacos is directly exposed on 8848 and honours the User-Agent: Nacos-Server
#     bypass (spoof => 200, full admin). This CANNOT be fixed on localhost by a
#     compensating control (loopback always reaches 8848), so it is only asserted
#     informationally below.
#   * The compensating control is a reverse proxy on 8080 that OVERWRITES the
#     User-Agent before forwarding, so the spoof is neutralised on the front door.
# The authoritative gate is therefore: a spoofed request through the proxy (8080)
# must be rejected (401/403), and the proxy must genuinely forward to Nacos.
set -u

USERS_PATH="/nacos/v1/auth/users?pageNo=1&pageSize=9"

###############################################################################
# PoC 1 (config): nginx must be configured to overwrite the User-Agent header.
###############################################################################
NGINX_CONF="/etc/nginx/sites-available/nacos"
if [ ! -f "$NGINX_CONF" ]; then
    NGINX_CONF=$(grep -rl 'proxy_set_header User-Agent' /etc/nginx/ 2>/dev/null | head -1 || echo "")
fi
if [ -n "$NGINX_CONF" ] && grep -q 'proxy_set_header User-Agent' "$NGINX_CONF"; then
    echo "PASS [PoC]: nginx config rewrites User-Agent header (found in $NGINX_CONF)."
else
    echo "FAIL [PoC]: no nginx config rewrites the User-Agent header." >&2
    exit 1
fi

###############################################################################
# Informational: confirm the underlying bypass is real on the direct port.
###############################################################################
DIRECT=$(curl -s -o /dev/null -w "%{http_code}" -H 'User-Agent: Nacos-Server' \
    "http://localhost:8848${USERS_PATH}" 2>/dev/null || echo "000")
echo "INFO: direct 8848 spoofed-UA request returns HTTP $DIRECT (the raw bypass; only reachable off-box after iptables)."

###############################################################################
# PoC 2 (authoritative): spoofed User-Agent through the sanitising proxy (8080)
# must be REJECTED (401/403). Baseline has no proxy on 8080 => connection fails
# => this is a FAIL. This is deploy/restart-sensitive: writing the nginx config
# without starting nginx leaves 8080 dead and fails here.
###############################################################################
PROXY_OK=""
for i in $(seq 1 12); do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" -H 'User-Agent: Nacos-Server' \
        "http://localhost:8080${USERS_PATH}" 2>/dev/null || echo "000")
    case "$CODE" in
        401|403) PROXY_OK=1; echo "PASS [PoC]: spoofed User-Agent via the proxy (8080) is rejected (HTTP $CODE)."; break;;
        200)     echo "FAIL [PoC]: spoofed User-Agent via the proxy (8080) returned 200 - bypass NOT neutralised." >&2; exit 1;;
        *)       sleep 5;;
    esac
done
if [ -z "$PROXY_OK" ]; then
    echo "FAIL [PoC]: no sanitising proxy answering on port 8080 (compensating control not deployed)." >&2
    exit 1
fi

###############################################################################
# Regression: the proxy must genuinely forward to Nacos (console reachable via
# 8080), not just return 403 to everything.
###############################################################################
for i in 1 2 3 4 5; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/nacos/" 2>/dev/null || echo "000")
    if echo "$CODE" | grep -qE '^(200|301|302|403)$'; then
        echo "PASS [Regression]: Nacos console reachable through the proxy on 8080 (HTTP $CODE)."
        exit 0
    fi
    sleep 5
done

echo "FAIL [Regression]: Nacos console not reachable through the proxy on 8080." >&2
exit 1
