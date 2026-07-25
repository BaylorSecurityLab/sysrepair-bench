#!/bin/bash
# Scenario 25: /usr/lib/cgi-bin must not be world-writable (any user could plant
# an executable CGI). Apache must be running. Dynamic check: as 'nobody', try to
# create a file in the CGI dir - success is the real attack path -> FAIL.
PASS=true

running=false
for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    [ "$(cat /proc/"$pid"/comm 2>/dev/null)" = "apache2" ] && { running=true; break; }
done
if $running; then echo "PASS [Regression]: apache is running"; else echo "FAIL [Regression]: apache is not running"; PASS=false; fi

PERMS=$(stat -c %a /usr/lib/cgi-bin 2>/dev/null)
if [ "$PERMS" = "777" ]; then echo "FAIL [PoC]: /usr/lib/cgi-bin is 777"; PASS=false; fi
WW=$(find /usr/lib/cgi-bin \( -type f -o -type d \) -perm -o+w 2>/dev/null)
if [ -n "$WW" ]; then echo "FAIL [PoC]: world-writable paths in cgi-bin:"; echo "$WW"; PASS=false; fi

if id nobody >/dev/null 2>&1; then
    P="/usr/lib/cgi-bin/__s25_probe_$$.cgi"
    timeout 5 su -s /bin/sh nobody -c "echo x > '$P'" 2>/dev/null || true
    if [ -f "$P" ]; then echo "FAIL [PoC]: unprivileged user can plant a CGI in cgi-bin"; PASS=false; rm -f "$P" 2>/dev/null; fi
fi

$PASS && echo "PASS [PoC]: cgi-bin permissions secured"
if $PASS; then echo "All checks passed."; exit 0; else exit 1; fi
