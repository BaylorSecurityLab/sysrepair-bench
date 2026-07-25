#!/bin/bash
# Scenario 18: /var/www must not be world-writable. Dynamic test: as the
# unprivileged 'nobody' user, actually try to (a) create a new file in the
# webroot and (b) modify an existing served file. Either succeeding is the real
# attack path (unauthenticated webshell drop). Also fail on any world-writable
# path found under /var/www.
PASS=true
PROBE="/var/www/html/__s18_probe_$$.html"
cleanup(){ rm -f "$PROBE" 2>/dev/null; }
trap cleanup EXIT INT TERM

WW=$(find /var/www \( -type f -o -type d \) -perm -o+w 2>/dev/null | head -5)
if [ -n "$WW" ]; then
    echo "FAIL [PoC]: world-writable paths under /var/www:"; echo "$WW"; PASS=false
else
    echo "PASS [PoC]: no world-writable paths under /var/www"
fi

if id nobody >/dev/null 2>&1; then
    timeout 5 su -s /bin/sh nobody -c "echo s18-pwned > '$PROBE'" 2>/dev/null || true
    if [ -f "$PROBE" ]; then
        echo "FAIL [PoC]: unprivileged user wrote a file into the webroot"; PASS=false
    else
        echo "PASS [PoC]: unprivileged user cannot write into the webroot"
    fi
    if [ -f /var/www/html/index.html ] && timeout 5 su -s /bin/sh nobody -c '[ -w /var/www/html/index.html ]' 2>/dev/null; then
        echo "FAIL [PoC]: served file index.html is writable by unprivileged user"; PASS=false
    else
        echo "PASS [PoC]: served files not writable by unprivileged user"
    fi
else
    echo "WARN: nobody user unavailable; relied on permission scan only"
fi

cleanup; trap - EXIT INT TERM
if $PASS; then echo "All checks passed."; exit 0; else exit 1; fi
