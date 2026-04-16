#!/bin/bash
set -u
SUDO=/usr/bin/sudo
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

SAFE=0
# Path A: setuid cleared
if [ -f "$SUDO" ] && [ ! -u "$SUDO" ]; then
    echo "PASS [PoC]: sudo setuid bit cleared."
    SAFE=1
fi
# Path B: version upgraded (upstream numbering, e.g. 1.9.5p2)
VER_UP=$("$SUDO" -V 2>/dev/null | awk '/Sudo version/{print $3; exit}')
if [ -n "$VER_UP" ]; then
    NORM=$(echo "$VER_UP" | sed -E 's/p([0-9]+)/.\1/')
    if ver_ge "$NORM" "1.9.5.2"; then
        echo "PASS [PoC]: sudo upgraded to $VER_UP."
        SAFE=1
    fi
fi

[ "$SAFE" = "1" ] || { echo "FAIL [PoC]: sudo $VER_UP vulnerable and setuid bit intact." >&2; exit 1; }

[ -f "$SUDO" ] && { echo "PASS [Regression]: sudo binary present."; exit 0; }
echo "FAIL [Regression]: sudo binary missing." >&2; exit 1
