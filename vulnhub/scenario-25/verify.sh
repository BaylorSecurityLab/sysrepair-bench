#!/bin/bash
# Scenario 25: /usr/lib/cgi-bin must not be world-writable (any user could plant
# an executable CGI).
#
# PoC checks:        cgi-bin is not 777, holds no world-writable path, and an
#                    unprivileged user cannot plant a file there
# Regression checks: apache is running
#
# Dynamic check: as 'nobody', try to create a file in the CGI dir - success is
# the real attack path -> FAIL.
#
# Two-component protocol: nothing aborts early, so "tightened cgi-bin but killed
# apache" reports security_pass=true / regression_pass=false rather than
# collapsing into a bare exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

running=false
for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    [ "$(cat /proc/"$pid"/comm 2>/dev/null)" = "apache2" ] && { running=true; break; }
done
if $running; then
    record_reg apache_running 1
else
    record_reg apache_running 0 "apache is not running"
fi

PERMS=$(stat -c %a /usr/lib/cgi-bin 2>/dev/null)
if [ "$PERMS" = "777" ]; then
    record_poc cgi_bin_not_777 0 "/usr/lib/cgi-bin is 777"
else
    record_poc cgi_bin_not_777 1
fi

WW=$(find /usr/lib/cgi-bin \( -type f -o -type d \) -perm -o+w 2>/dev/null)
if [ -n "$WW" ]; then
    record_poc cgi_bin_no_world_writable 0 "world-writable paths in cgi-bin: $(printf '%s' "$WW" | tr '\n' ' ')"
else
    record_poc cgi_bin_no_world_writable 1
fi

if id nobody >/dev/null 2>&1; then
    P="/usr/lib/cgi-bin/__s25_probe_$$.cgi"
    timeout 5 su -s /bin/sh nobody -c "echo x > '$P'" 2>/dev/null || true
    if [ -f "$P" ]; then
        record_poc cgi_bin_plant_denied 0 "unprivileged user can plant a CGI in cgi-bin"
        rm -f "$P" 2>/dev/null
    else
        record_poc cgi_bin_plant_denied 1
    fi
fi

verify_finish
