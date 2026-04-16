#!/bin/bash
set -u
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

VER=$(/usr/local/bin/runc --version 2>/dev/null | awk '/^runc version/{print $3; exit}')
[ -z "$VER" ] && { echo "FAIL [PoC]: runc --version returned nothing." >&2; exit 1; }

if ver_ge "$VER" "1.1.12"; then
    echo "PASS [PoC]: runc upgraded to $VER."
else
    echo "FAIL [PoC]: runc $VER vulnerable (need >= 1.1.12)." >&2; exit 1
fi

/usr/local/bin/runc --help >/dev/null 2>&1 && { echo "PASS [Regression]: runc functional."; exit 0; }
echo "FAIL [Regression]: runc --help failed." >&2; exit 1
