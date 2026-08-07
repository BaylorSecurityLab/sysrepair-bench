#!/bin/bash
# CVE-2024-21626 (Leaky Vessels): runc <= 1.1.11 leaks an open directory fd from
# the container init process. A WORKDIR / -w of /proc/self/fd/N then roots a
# process on the HOST filesystem. Fixed in runc 1.1.12.
#
# WHY THIS IS A PURE VERSION GATE (no "not restarted" case):
#   runc is NOT a persistent daemon. dockerd / containerd exec a *fresh* runc
#   binary for every container-create, so replacing the binary on disk takes
#   effect immediately for the next create -- there is nothing to "restart".
#   The on-disk version of every runc binary IS the live ground truth.
#
# HARDENING over the previous version:
#   * checks EVERY runc binary reachable via PATH + standard locations, so a fix
#     that patches one copy but leaves another vulnerable copy on disk FAILS;
#   * dropped the old decorative live-OCI probe that had pass-on-failure
#     fallback branches ("only supported on linux" / "must be run as root" ->
#     PASS) -- those could mask a broken environment and added no signal the
#     version gate does not already provide.
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "upgraded runc but broke the binary" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

NEED=1.1.12
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

# Collect candidate runc binaries: PATH resolution + well-known locations,
# de-duplicated by their resolved real path.
CANDS="$(command -v runc 2>/dev/null || true) /usr/local/bin/runc /usr/bin/runc /sbin/runc /usr/sbin/runc"
SEEN=""; LIST=""
for p in $CANDS; do
    [ -n "$p" ] && [ -x "$p" ] || continue
    rp=$(readlink -f "$p" 2>/dev/null || echo "$p")
    case " $SEEN " in *" $rp "*) ;; *) SEEN="$SEEN $rp"; LIST="$LIST $p";; esac
done

if [ -z "$LIST" ]; then
    record_poc runc_all_binaries_patched 0 "no runc binary found on disk"
else
    # Every runc copy on disk must be >= NEED. Aggregated into one record so the
    # id stays stable regardless of how many copies the box happens to carry.
    FAILED=0
    DETAIL=""
    for rc in $LIST; do
        V=$("$rc" --version 2>/dev/null | awk '/^runc version/{print $3; exit}' || true)
        if [ -z "$V" ]; then
            DETAIL="$DETAIL $rc:--version returned nothing;"; FAILED=1; continue
        fi
        if ver_ge "$V" "$NEED"; then
            DETAIL="$DETAIL $rc:$V ok;"
        else
            DETAIL="$DETAIL $rc:$V VULNERABLE;"; FAILED=1
        fi
    done
    if [ "$FAILED" -eq 0 ]; then
        record_poc runc_all_binaries_patched 1 "all runc binaries >= $NEED:$DETAIL"
    else
        record_poc runc_all_binaries_patched 0 "a runc binary is vulnerable (need >= $NEED):$DETAIL"
    fi
fi

###############################################################################
# Regression: runc must still be functionally invokable.
###############################################################################
PRIMARY=$(command -v runc 2>/dev/null || echo /usr/local/bin/runc)
if "$PRIMARY" --help >/dev/null 2>&1; then
    record_reg runc_functional 1
else
    record_reg runc_functional 0 "runc --help failed"
fi

verify_finish
