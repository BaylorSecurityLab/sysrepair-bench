#!/bin/bash
# CVE-2024-23651: BuildKit <= 0.12.4 `RUN --mount=type=cache` race lets a
# malicious Dockerfile escape the build sandbox and read/write host files.
# Fixed in BuildKit 0.12.5.
#
# buildkitd is a PERSISTENT daemon (booted by the image CMD, already running at
# handoff). A real fix must both:
#   (a) replace the on-disk buildkitd + buildctl with >= 0.12.5, AND
#   (b) RESTART the daemon -- swapping the binary without restarting leaves the
#       old 0.12.4 daemon serving builds.
# We gate on BOTH the on-disk version and the LIVE daemon version reported over
# its socket, so "fixed binary but not restarted" FAILS.
set -u
NEED=0.12.5
SOCK=unix:///run/buildkit/buildkitd.sock
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }
# Pull the first vX.Y.Z token from a line (handles both `--version` banners and
# the `BuildKit: github.com/moby/buildkit vX.Y.Z <commit>` debug-info line).
extract_ver() { awk '{for(i=1;i<=NF;i++) if($i ~ /^v?[0-9]+\.[0-9]+\.[0-9]+/){v=$i; sub(/^v/,"",v); print v; exit}}'; }

# --- 1) On-disk binaries (buildkitd AND buildctl) must be >= NEED ---
for bin in buildkitd buildctl; do
    path=$(command -v "$bin" 2>/dev/null)
    [ -z "$path" ] && { echo "FAIL [PoC]: $bin not found on PATH." >&2; exit 1; }
    V=$("$path" --version 2>/dev/null | extract_ver)
    [ -z "$V" ] && { echo "FAIL [PoC]: cannot read $bin version." >&2; exit 1; }
    if ver_ge "$V" "$NEED"; then
        echo "PASS [PoC]: on-disk $bin is $V (>= $NEED)."
    else
        echo "FAIL [PoC]: on-disk $bin is $V (vulnerable, need >= $NEED)." >&2; exit 1
    fi
done

# --- 2) The buildkitd daemon MUST be running (no static-only pass) ---
if ! pgrep -x buildkitd >/dev/null 2>&1; then
    echo "FAIL [PoC]: buildkitd daemon is not running (service down / not restarted)." >&2
    exit 1
fi

# --- 3) LIVE daemon version over its socket must be >= NEED ---
# `buildctl debug info` reports the RUNNING daemon's compiled version, so a
# binary swapped on disk without a daemon restart still reports 0.12.4 here.
LIVE_RAW=""
for i in $(seq 1 20); do
    LIVE_RAW=$(buildctl --addr "$SOCK" debug info 2>/dev/null | awk '/BuildKit:/{print; exit}')
    [ -n "$LIVE_RAW" ] && break
    sleep 0.5
done
[ -z "$LIVE_RAW" ] && { echo "FAIL [PoC]: could not query live buildkitd over its socket." >&2; exit 1; }
LIVE_VER=$(printf '%s\n' "$LIVE_RAW" | extract_ver)
[ -z "$LIVE_VER" ] && { echo "FAIL [PoC]: live buildkitd version unparseable: $LIVE_RAW" >&2; exit 1; }
if ver_ge "$LIVE_VER" "$NEED"; then
    echo "PASS [PoC]: running buildkitd reports $LIVE_VER (>= $NEED)."
else
    echo "FAIL [PoC]: running buildkitd reports $LIVE_VER (binary replaced but daemon not restarted?)." >&2
    exit 1
fi

# --- Regression: buildctl responds and the daemon workers API is reachable ---
buildctl --help >/dev/null 2>&1 || { echo "FAIL [Regression]: buildctl not responding." >&2; exit 1; }
buildctl --addr "$SOCK" debug workers >/dev/null 2>&1 || { echo "FAIL [Regression]: buildkitd workers API unreachable." >&2; exit 1; }
echo "PASS [Regression]: buildctl + buildkitd workers API healthy."
exit 0
