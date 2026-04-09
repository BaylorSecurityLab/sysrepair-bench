#!/bin/bash
PERMS=$(stat -c %a /usr/lib/cgi-bin 2>/dev/null)
if [ "$PERMS" = "777" ]; then
    echo "FAIL [PoC]: /usr/lib/cgi-bin is 777."; exit 1
fi
WW=$(find /usr/lib/cgi-bin -perm -o+w 2>/dev/null)
if [ -n "$WW" ]; then echo "FAIL [PoC]: World-writable files in cgi-bin."; exit 1; fi
echo "PASS [PoC]: CGI-bin permissions secured."
if pgrep -x apache2 > /dev/null 2>&1; then echo "PASS [Regression]: Apache running."
else echo "FAIL [Regression]: Apache not running."; exit 1; fi
echo "All checks passed."; exit 0
