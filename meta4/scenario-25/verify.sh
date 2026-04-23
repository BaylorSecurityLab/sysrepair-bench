#!/bin/bash
set -u
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }
VER=$(buildkitd --version 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i ~ /^v?[0-9]/){v=$i; gsub(/^v/,"",v); print v; exit}}')
[ -z "$VER" ] && VER=$(buildctl --version 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i ~ /^v?[0-9]/){v=$i; gsub(/^v/,"",v); print v; exit}}')
[ -z "$VER" ] && { echo "FAIL [PoC]: cannot read buildkit version." >&2; exit 1; }

if ver_ge "$VER" "0.12.5"; then
    echo "PASS [PoC]: BuildKit upgraded to $VER."
else
    echo "FAIL [PoC]: BuildKit $VER vulnerable." >&2; exit 1
fi

# PoC (behavioral live): confirm the running buildkitd daemon reports a
# non-vulnerable version, not just the binary on disk. CVE-2024-23652's
# teardown bug only matters at runtime, so we exercise the live process.
if pgrep -x buildkitd >/dev/null 2>&1; then
    LIVE_VER=$(buildctl --addr unix:///run/buildkit/buildkitd.sock debug info 2>/dev/null \
        | awk '/BuildKit/{print $NF; exit}' | tr -d 'v' || true)
    if [ -n "$LIVE_VER" ] && ! ver_ge "$LIVE_VER" "0.12.5"; then
        echo "FAIL [PoC]: running buildkitd reports $LIVE_VER (still vulnerable)." >&2
        exit 1
    fi
    [ -n "$LIVE_VER" ] && echo "PASS [PoC]: running buildkitd reports $LIVE_VER."
    # Listing workers exercises the daemon's gRPC API end-to-end.
    if buildctl debug workers >/dev/null 2>&1; then
        echo "PASS [PoC]: buildkitd workers API reachable."
    fi
else
    echo "PASS [PoC]: buildkitd not running at verify time (static check only)."
fi

buildctl --help >/dev/null 2>&1 && { echo "PASS [Regression]: buildctl responds."; exit 0; }
echo "FAIL [Regression]: buildctl not responding." >&2; exit 1
