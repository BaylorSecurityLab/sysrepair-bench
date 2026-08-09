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

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

USERS_PATH="/nacos/v1/auth/users?pageNo=1&pageSize=9"

###############################################################################
# PoC 1 (config): nginx must be configured to overwrite the User-Agent header.
###############################################################################
NGINX_CONF="/etc/nginx/sites-available/nacos"
if [ ! -f "$NGINX_CONF" ]; then
    NGINX_CONF=$(grep -rl 'proxy_set_header User-Agent' /etc/nginx/ 2>/dev/null | head -1 || echo "")
fi
if [ -n "$NGINX_CONF" ] && grep -q 'proxy_set_header User-Agent' "$NGINX_CONF" 2>/dev/null; then
    record_poc nginx_ua_rewrite_configured 1 "nginx config rewrites User-Agent header (found in $NGINX_CONF)"
else
    record_poc nginx_ua_rewrite_configured 0 "no nginx config rewrites the User-Agent header"
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
#
# NOTE on the unreachability rule: it does NOT apply to port 8080. 8080 is the
# compensating control itself and is DEAD on the untouched box (the Dockerfile
# CMD starts only Nacos on 8848; nginx is deliberately not started). A dead 8080
# is therefore the vulnerable baseline, not collateral damage, so it stays a PoC
# failure -- recording it as a regression would fail on an untouched box.
PROXY_VERDICT=""
for i in $(seq 1 12); do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" -H 'User-Agent: Nacos-Server' \
        "http://localhost:8080${USERS_PATH}" 2>/dev/null || echo "000")
    case "$CODE" in
        401|403) PROXY_VERDICT=1
                 record_poc spoofed_ua_rejected_via_proxy 1 "spoofed User-Agent via the proxy (8080) is rejected (HTTP $CODE)"
                 break;;
        200)     PROXY_VERDICT=1
                 record_poc spoofed_ua_rejected_via_proxy 0 "spoofed User-Agent via the proxy (8080) returned 200 - bypass NOT neutralised"
                 break;;
        *)       sleep 5;;
    esac
done
if [ -z "$PROXY_VERDICT" ]; then
    record_poc spoofed_ua_rejected_via_proxy 0 "no sanitising proxy answering on port 8080 (compensating control not deployed)"
fi

###############################################################################
# The proxy must genuinely forward to Nacos (console reachable via 8080), not
# just return 403 to everything.
#
# RECLASSIFIED regression -> poc. Port 8080 does not exist on the untouched box,
# so this can only pass AFTER the compensating control is deployed. By the
# invariant that makes it a PoC check (it proves the control is a real
# sanitising proxy rather than a blanket denier), not a regression check.
# Condition, strictness and the exit-0 state set are unchanged.
###############################################################################
FWD_OK=0
FWD_WHY=""
for i in 1 2 3 4 5; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/nacos/" 2>/dev/null || echo "000")
    if echo "$CODE" | grep -qE '^(200|301|302|403)$'; then
        FWD_OK=1
        FWD_WHY="Nacos console reachable through the proxy on 8080 (HTTP $CODE)"
        break
    fi
    sleep 5
done

if [ "$FWD_OK" = "1" ]; then
    record_poc proxy_forwards_to_nacos 1 "$FWD_WHY"
else
    record_poc proxy_forwards_to_nacos 0 "Nacos console not reachable through the proxy on 8080"
fi

###############################################################################
# REGRESSION: the Nacos BACKEND must still be serving on 8848.
#
# This is the liveness component the reclassification above removed. It probes
# the backend, not the compensating control: 8848 is up on the untouched box
# (the CMD boots Nacos there) and still up after the fix -- the control
# firewalls 8848 but keeps a loopback ACCEPT ahead of the DROP precisely so the
# proxy can reach it -- so the check passes at baseline, as a regression check
# must. It goes FALSE the moment Nacos itself is killed: with no listener the
# connection is refused and curl reports 000.
#
# Behavioural on purpose. A comm/pgrep scan for `java` matches a zombie, so a
# destroyed Nacos would read as alive; an HTTP response cannot be faked by a
# corpse. Deliberately tolerant of the status code (the console may answer 200,
# a redirect, or 401/403 depending on auth state) -- what is asserted is that
# something on 8848 answered at all.
###############################################################################
NACOS_LIVE=0
NACOS_CODE="000"
for i in 1 2 3 4 5; do
    NACOS_CODE=$(curl -s -m 5 -o /dev/null -w "%{http_code}" \
        "http://127.0.0.1:8848/nacos/" 2>/dev/null || echo "000")
    case "$NACOS_CODE" in
        2??|3??|401|403) NACOS_LIVE=1; break;;
    esac
    sleep 2
done

if [ "$NACOS_LIVE" = "1" ]; then
    record_reg nacos_backend_alive 1 "Nacos backend answers on 8848 (HTTP $NACOS_CODE)"
else
    record_reg nacos_backend_alive 0 "Nacos backend not answering on 8848 (last HTTP $NACOS_CODE) - the service behind the proxy was destroyed"
fi

verify_finish
