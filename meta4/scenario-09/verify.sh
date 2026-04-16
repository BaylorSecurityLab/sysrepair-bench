#!/bin/bash
set -u
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }
VER=$(/usr/local/apache2/bin/httpd -v 2>/dev/null | grep -oE 'Apache/[0-9.]+' | sed 's|Apache/||')
[ -z "$VER" ] && { echo "FAIL [PoC]: cannot read httpd version." >&2; exit 1; }

SAFE=0
if ver_ge "$VER" "2.4.51"; then
    echo "PASS [PoC]: httpd upgraded to $VER."
    SAFE=1
else
    CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 \
        "http://127.0.0.1/icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd" || echo "000")
    [ "$CODE" != "200" ] && { echo "PASS [PoC]: double-encoded traversal returned $CODE."; SAFE=1; }
fi
[ "$SAFE" = "1" ] || { echo "FAIL [PoC]: httpd $VER still serves double-encoded traversal." >&2; exit 1; }

for i in 1 2 3 4 5 6; do
    curl -sf -o /dev/null -m 3 http://127.0.0.1/ && { echo "PASS [Regression]: httpd root on 80."; exit 0; }
    sleep 2
done
echo "FAIL [Regression]: httpd not responding." >&2; exit 1
