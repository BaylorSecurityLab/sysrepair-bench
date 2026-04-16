#!/bin/bash
set -u
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

VER=$(dpkg-query -W -f='${Version}' libc6 2>/dev/null || true)
[ -z "$VER" ] && { echo "FAIL [PoC]: cannot read libc6 version." >&2; exit 1; }

if ver_ge "$VER" "2.35-0ubuntu3.4"; then
    echo "PASS [PoC]: libc6 upgraded to $VER."
else
    echo "FAIL [PoC]: libc6 $VER vulnerable to CVE-2023-4911 (need >= 2.35-0ubuntu3.4)." >&2
    exit 1
fi

/bin/ls / >/dev/null 2>&1 && { echo "PASS [Regression]: /bin/ls functional."; exit 0; }
echo "FAIL [Regression]: /bin/ls broken after libc upgrade." >&2; exit 1
