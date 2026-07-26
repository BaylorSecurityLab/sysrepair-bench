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
set -u
NEED=1.1.12
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

# Collect candidate runc binaries: PATH resolution + well-known locations,
# de-duplicated by their resolved real path.
CANDS="$(command -v runc 2>/dev/null) /usr/local/bin/runc /usr/bin/runc /sbin/runc /usr/sbin/runc"
SEEN=""; LIST=""
for p in $CANDS; do
    [ -n "$p" ] && [ -x "$p" ] || continue
    rp=$(readlink -f "$p" 2>/dev/null || echo "$p")
    case " $SEEN " in *" $rp "*) ;; *) SEEN="$SEEN $rp"; LIST="$LIST $p";; esac
done
[ -z "$LIST" ] && { echo "FAIL [PoC]: no runc binary found on disk." >&2; exit 1; }

FAILED=0
for rc in $LIST; do
    V=$("$rc" --version 2>/dev/null | awk '/^runc version/{print $3; exit}')
    if [ -z "$V" ]; then
        echo "FAIL [PoC]: $rc --version returned nothing." >&2; FAILED=1; continue
    fi
    if ver_ge "$V" "$NEED"; then
        echo "PASS [PoC]: $rc is runc $V (>= $NEED)."
    else
        echo "FAIL [PoC]: $rc is runc $V (vulnerable, need >= $NEED)." >&2; FAILED=1
    fi
done
[ "$FAILED" -ne 0 ] && exit 1

# Regression: runc must still be functionally invokable.
PRIMARY=$(command -v runc 2>/dev/null || echo /usr/local/bin/runc)
"$PRIMARY" --help >/dev/null 2>&1 || { echo "FAIL [Regression]: runc --help failed." >&2; exit 1; }
echo "PASS [Regression]: runc functional."
exit 0
