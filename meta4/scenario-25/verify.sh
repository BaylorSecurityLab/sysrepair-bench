#!/bin/bash
# CVE-2024-23652: BuildKit <= 0.12.4 follows attacker-planted symlinks during
# teardown of a `RUN --mount=type=cache` mount, letting a malicious Dockerfile
# unlink/replace arbitrary host files. Fixed in BuildKit 0.12.5.
#
# buildkitd is a PERSISTENT daemon (booted by the image CMD, already running at
# handoff). A real fix must both:
#   (a) replace the on-disk buildkitd + buildctl with >= 0.12.5, AND
#   (b) RESTART the daemon -- swapping the binary without restarting leaves the
#       old 0.12.4 daemon serving builds.
# We gate on BOTH the on-disk version and the LIVE daemon version reported over
# its socket, so "fixed binary but not restarted" FAILS.
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "upgraded BuildKit but killed buildkitd" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

NEED=0.12.5
SOCK=unix:///run/buildkit/buildkitd.sock
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }
# Pull the first vX.Y.Z token from a line (handles both `--version` banners and
# the `BuildKit: github.com/moby/buildkit vX.Y.Z <commit>` debug-info line).
extract_ver() { awk '{for(i=1;i<=NF;i++) if($i ~ /^v?[0-9]+\.[0-9]+\.[0-9]+/){v=$i; sub(/^v/,"",v); print v; exit}}'; }

# --- 1) On-disk binaries (buildkitd AND buildctl) must be >= NEED ---
for bin in buildkitd buildctl; do
    path=$(command -v "$bin" 2>/dev/null || true)
    if [ -z "$path" ]; then
        record_poc "${bin}_ondisk_patched" 0 "$bin not found on PATH"
        continue
    fi
    V=$("$path" --version 2>/dev/null | extract_ver || true)
    if [ -z "$V" ]; then
        record_poc "${bin}_ondisk_patched" 0 "cannot read $bin version"
    elif ver_ge "$V" "$NEED"; then
        record_poc "${bin}_ondisk_patched" 1 "on-disk $bin is $V (>= $NEED)"
    else
        record_poc "${bin}_ondisk_patched" 0 "on-disk $bin is $V (vulnerable, need >= $NEED)"
    fi
done

# --- 2) The buildkitd daemon must be running ---
# Reclassified from PoC to REGRESSION: this condition fails only when the daemon
# is DOWN, which is service damage, not an open vulnerability. The "binary
# replaced but never restarted" case it was originally guarding is caught by the
# live-version PoC below, which is unaffected by the relabel.
DAEMON_UP=0
if pgrep -x buildkitd >/dev/null 2>&1; then
    DAEMON_UP=1
    record_reg buildkitd_running 1
else
    record_reg buildkitd_running 0 "buildkitd daemon is not running (service down / not restarted)"
fi

# --- 3) LIVE daemon version over its socket must be >= NEED ---
# `buildctl debug info` reports the RUNNING daemon's compiled version, so a
# binary swapped on disk without a daemon restart still reports 0.12.4 here.
LIVE_RAW=""
if [ "$DAEMON_UP" = "1" ]; then
    for i in $(seq 1 20); do
        LIVE_RAW=$(buildctl --addr "$SOCK" debug info 2>/dev/null | awk '/BuildKit:/{print; exit}' || true)
        [ -n "$LIVE_RAW" ] && break
        sleep 0.5
    done
fi
LIVE_VER=""
[ -n "$LIVE_RAW" ] && LIVE_VER=$(printf '%s\n' "$LIVE_RAW" | extract_ver || true)

if [ -n "$LIVE_VER" ]; then
    record_reg buildkitd_socket_queryable 1
    if ver_ge "$LIVE_VER" "$NEED"; then
        record_poc buildkitd_live_patched 1 "running buildkitd reports $LIVE_VER (>= $NEED)"
    else
        record_poc buildkitd_live_patched 0 "running buildkitd reports $LIVE_VER (binary replaced but daemon not restarted?)"
    fi
else
    # The daemon could not be interrogated at all. That is an unreachable
    # service, not a closed vulnerability -- record it as regression damage and
    # leave the live-version PoC unmeasured, so killing buildkitd can never read
    # as having patched it.
    record_reg buildkitd_socket_queryable 0 "could not query live buildkitd over its socket${LIVE_RAW:+ (unparseable: $LIVE_RAW)}"
fi

# --- Regression: buildctl responds and the daemon workers API is reachable ---
if buildctl --help >/dev/null 2>&1; then
    record_reg buildctl_responds 1
else
    record_reg buildctl_responds 0 "buildctl not responding"
fi
if buildctl --addr "$SOCK" debug workers >/dev/null 2>&1; then
    record_reg buildkitd_workers_api 1
else
    record_reg buildkitd_workers_api 0 "buildkitd workers API unreachable"
fi

verify_finish
