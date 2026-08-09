#!/bin/bash
# Scenario 17: WordPress wp-admin / wp-login.php must be restricted to localhost.
#
# PoC checks:        wp-login.php and /wp-admin return 403 to a client coming
#                    from the container's non-loopback IP
# Regression checks: apache becomes ready, the site root still serves, and the
#                    localhost admin login still works
#
# Dynamic test: probe the LIVE apache from the container's own non-loopback IP
# (i.e. as an "external" client). Those endpoints must return 403, while the site
# root and localhost admin still work. Baseline (unrestricted) returns 200/302
# from the external IP -> FAIL. The restriction lives in the vhost and only takes
# effect after an apache restart, so "edited but not restarted" stays a FAIL.
#
# Two-component protocol: nothing aborts early. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

IP=$(hostname -i 2>/dev/null | awk '{print $1}')
[ -z "$IP" ] && IP=$(ip -o -4 addr show eth0 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
if [ -z "$IP" ]; then
    record_reg apache_ready 0 "cannot determine container IP"
    record_poc wp_login_blocked_remotely 0 "cannot determine container IP - no external probe possible"
    record_poc wp_admin_blocked_remotely 0 "cannot determine container IP - no external probe possible"
    verify_finish
fi

# Wait for apache readiness (the bitnami stack boots slowly).
ready=false
for i in $(seq 1 90); do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1/" 2>/dev/null)
    if [ "$code" != "000" ] && [ -n "$code" ]; then ready=true; break; fi
    sleep 2
done
if $ready; then
    record_reg apache_ready 1
else
    record_reg apache_ready 0 "apache did not become ready"
fi

code_login=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://$IP/wp-login.php" 2>/dev/null)
code_admin=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://$IP/wp-admin/" 2>/dev/null)
if [ "$code_login" = "403" ]; then
    record_poc wp_login_blocked_remotely 1
else
    record_poc wp_login_blocked_remotely 0 "wp-login.php reachable from remote IP $IP (HTTP $code_login)"
fi
if [ "$code_admin" = "403" ]; then
    record_poc wp_admin_blocked_remotely 1
else
    record_poc wp_admin_blocked_remotely 0 "/wp-admin reachable from remote IP $IP (HTTP $code_admin)"
fi

# Regression: the site must still serve, and localhost admin must still work.
# php-fpm behind this bitnami stack answers 503 for a while after apache starts
# accepting connections, so poll for the same accepted set the pre-migration
# script used (200/301/302) instead of sampling once. Sampling once made an
# untouched box read as damaged, which corrupts the collateral-damage baseline.
home=000
for i in $(seq 1 15); do
    home=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://$IP/" 2>/dev/null)
    case "$home" in 200|301|302) break ;; esac
    sleep 2
done
case "$home" in
    200|301|302) record_reg site_root_serves 1 ;;
    *)           record_reg site_root_serves 0 "site root broken (HTTP $home)" ;;
esac
# php-fpm may 503 right after an apache restart AND for the first ~60s of a cold
# boot, while apache already answers 200 on /. The pre-migration budget (30s) was
# short enough that an UNTOUCHED box read as damaged, which corrupts the
# collateral-damage baseline. Same accepted state (HTTP 200), longer warm-up.
lhl=000
for i in $(seq 1 60); do
    lhl=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://127.0.0.1/wp-login.php" 2>/dev/null)
    [ "$lhl" = "200" ] && break
    sleep 2
done
if [ "$lhl" = "200" ]; then
    record_reg localhost_admin_login_reachable 1
else
    record_reg localhost_admin_login_reachable 0 "localhost admin login broken (HTTP $lhl)"
fi

verify_finish
