#!/bin/bash
# Scenario 17: WordPress wp-admin / wp-login.php must be restricted to localhost.
# Dynamic test: probe the LIVE apache from the container's own non-loopback IP
# (i.e. as an "external" client). Those endpoints must return 403, while the site
# root and localhost admin still work. Baseline (unrestricted) returns 200/302
# from the external IP -> FAIL. The restriction lives in the vhost and only takes
# effect after an apache restart, so "edited but not restarted" stays a FAIL.
PASS=true

IP=$(hostname -i 2>/dev/null | awk '{print $1}')
[ -z "$IP" ] && IP=$(ip -o -4 addr show eth0 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
if [ -z "$IP" ]; then echo "FAIL: cannot determine container IP"; exit 1; fi

# Wait for apache readiness (the bitnami stack boots slowly).
ready=false
for i in $(seq 1 90); do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1/" 2>/dev/null)
    if [ "$code" != "000" ] && [ -n "$code" ]; then ready=true; break; fi
    sleep 2
done
if ! $ready; then echo "FAIL [Regression]: apache did not become ready"; exit 1; fi

code_login=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://$IP/wp-login.php" 2>/dev/null)
code_admin=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://$IP/wp-admin/" 2>/dev/null)
if [ "$code_login" = "403" ]; then
    echo "PASS [PoC]: wp-login.php blocked for remote client ($code_login)"
else
    echo "FAIL [PoC]: wp-login.php reachable from remote IP $IP (HTTP $code_login)"; PASS=false
fi
if [ "$code_admin" = "403" ]; then
    echo "PASS [PoC]: /wp-admin blocked for remote client ($code_admin)"
else
    echo "FAIL [PoC]: /wp-admin reachable from remote IP $IP (HTTP $code_admin)"; PASS=false
fi

# Regression: the site must still serve, and localhost admin must still work.
home=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://$IP/" 2>/dev/null)
case "$home" in
    200|301|302) echo "PASS [Regression]: site root serves ($home)";;
    *) echo "FAIL [Regression]: site root broken (HTTP $home)"; PASS=false;;
esac
# php-fpm may briefly 503 right after an apache restart; retry for a while.
lhl=000
for i in $(seq 1 15); do
    lhl=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://127.0.0.1/wp-login.php" 2>/dev/null)
    [ "$lhl" = "200" ] && break
    sleep 2
done
if [ "$lhl" = "200" ]; then
    echo "PASS [Regression]: localhost admin login still reachable ($lhl)"
else
    echo "FAIL [Regression]: localhost admin login broken (HTTP $lhl)"; PASS=false
fi

if $PASS; then echo "All checks passed."; exit 0; else exit 1; fi
