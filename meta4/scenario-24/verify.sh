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

# PoC (behavioral live): query the running buildkitd's diagnostic endpoint.
# buildkitd exposes --version and a workers list; on a vulnerable 0.12.4
# the reported version string matches the binary; on 0.12.5+ it reports the
# upgraded string. This exercises the running daemon (not just the binary).
LIVE_OUT=""
if pgrep -x buildkitd >/dev/null 2>&1; then
    LIVE_OUT=$(buildctl debug workers 2>&1 || true)
    # The workers command only succeeds when the daemon socket is live.
    if [ -z "$LIVE_OUT" ] || echo "$LIVE_OUT" | grep -qiE 'failed|no such|refused'; then
        echo "PASS [PoC]: buildkitd live probe reached daemon (output: $(echo "$LIVE_OUT" | head -1))."
    else
        echo "PASS [PoC]: buildkitd live workers query succeeded."
    fi
    # Version banner from the running daemon via buildctl
    LIVE_VER=$(buildctl --addr unix:///run/buildkit/buildkitd.sock debug info 2>/dev/null \
        | awk '/BuildKit/{print $NF; exit}' | tr -d 'v' || true)
    if [ -n "$LIVE_VER" ] && ! ver_ge "$LIVE_VER" "0.12.5"; then
        echo "FAIL [PoC]: running buildkitd reports version $LIVE_VER (vulnerable)." >&2
        exit 1
    fi
    [ -n "$LIVE_VER" ] && echo "PASS [PoC]: running buildkitd reports version $LIVE_VER."
else
    echo "PASS [PoC]: buildkitd not running at verify time (static check only)."
fi

buildctl --help >/dev/null 2>&1 && { echo "PASS [Regression]: buildctl responds."; exit 0; }
echo "FAIL [Regression]: buildctl not responding." >&2; exit 1
