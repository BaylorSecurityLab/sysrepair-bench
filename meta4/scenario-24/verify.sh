#!/bin/bash
set -u
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

VER=$(buildkitd --version 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i ~ /^v?[0-9]/){v=$i; gsub(/^v/,"",v); print v; exit}}')
[ -z "$VER" ] && VER=$(buildctl --version 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i ~ /^v?[0-9]/){v=$i; gsub(/^v/,"",v); print v; exit}}')
[ -z "$VER" ] && { echo "FAIL [PoC]: cannot read buildkit version." >&2; exit 1; }

if ver_ge "$VER" "0.12.5"; then
    echo "PASS [PoC]: BuildKit upgraded to $VER."
else
    echo "FAIL [PoC]: BuildKit $VER vulnerable (need >= 0.12.5)." >&2; exit 1
fi

buildctl --help >/dev/null 2>&1 && { echo "PASS [Regression]: buildctl responds."; exit 0; }
echo "FAIL [Regression]: buildctl not responding." >&2; exit 1
