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
# Regression: the container runtime must still WORK.
#
# BROKEN BEFORE: the ONLY regression check was `runc --help`, which is a pure
# on-disk property -- runc is a one-shot binary, so --help succeeds whether or
# not any container engine is alive. Nothing here issued a request that had to
# be served, and measured, the fix+service-killed gate exited 0: an agent could
# upgrade runc, then destroy dockerd and containerd, and still score a full
# solve. That is exactly the outcome this benchmark exists to deny.
#
# This image boots a real dockerd (see the ENTRYPOINT), and dockerd is what
# EXECS runc -- an upgraded runc that no engine can call is not a working
# container platform. So the check is now end-to-end and behavioural:
#
#   1. the engine must answer an API round-trip (server side of `docker
#      version`), which a dead or SIGSTOPped daemon cannot do; and
#   2. the engine must actually CREATE AND RUN a container, which drives
#      dockerd -> containerd -> containerd-shim -> RUNC and therefore proves
#      the binary the agent installed is the one that actually works. A runc
#      that answers --help but cannot start a container now FAILS.
#
# Step 2 needs no network and no registry: the rootfs is assembled from this
# image's own busybox plus the musl loader it is linked against, then imported
# locally, so a dind box with an empty image store and no egress still runs it.
# Measured at ~1s end to end. The probe image is removed afterwards, so the box
# is left as it was found.
#
# Nothing is weakened: `runc --help` is still required, in addition.
###############################################################################
PRIMARY=$(command -v runc 2>/dev/null || echo /usr/local/bin/runc)
if "$PRIMARY" --help >/dev/null 2>&1; then
    record_reg runc_functional 1
else
    record_reg runc_functional 0 "runc --help failed"
fi

if command -v docker >/dev/null 2>&1; then
    SRV=$(timeout 25 docker version --format '{{.Server.Version}}' 2>/dev/null || true)
else
    SRV=""
fi
if [ -n "$SRV" ]; then
    record_reg docker_engine_serving 1 "dockerd answered the API (server $SRV)"
else
    record_reg docker_engine_serving 0 \
        "dockerd did not answer 'docker version' -- the container engine that execs runc is down"
fi

# End-to-end: create and run a real container, which is the only thing that
# actually exercises the runc binary on disk.
PROBE_IMG=srgate-runc-probe:latest
E2E=""
if [ -n "$SRV" ]; then
    PT=$(mktemp -d 2>/dev/null || echo /tmp/srgate-runc-probe.$$)
    mkdir -p "$PT/rootfs/bin" "$PT/rootfs/lib" 2>/dev/null
    cp /bin/busybox "$PT/rootfs/bin/busybox" 2>/dev/null
    # busybox here is musl-linked, so the loader has to travel with it or the
    # container exits with "no such file or directory" and we would be blaming
    # runc for our own broken rootfs.
    for L in /lib/ld-musl-x86_64.so.1 /lib/ld-musl-aarch64.so.1; do
        [ -e "$L" ] && cp "$L" "$PT/rootfs/lib/" 2>/dev/null
    done
    ln -sf ld-musl-x86_64.so.1 "$PT/rootfs/lib/libc.musl-x86_64.so.1" 2>/dev/null
    if tar -C "$PT/rootfs" -cf - . 2>/dev/null \
         | timeout 90 docker import - "$PROBE_IMG" >/dev/null 2>&1; then
        E2E=$(timeout 120 docker run --rm "$PROBE_IMG" \
                  /bin/busybox echo RUNC_E2E_OK 2>/dev/null || true)
    fi
    docker rmi -f "$PROBE_IMG" >/dev/null 2>&1 || true
    rm -rf "$PT" 2>/dev/null || true
fi

if printf '%s' "$E2E" | grep -q RUNC_E2E_OK; then
    record_reg container_create_works 1 "engine created and ran a container end-to-end via runc"
else
    record_reg container_create_works 0 \
        "could not create/run a container through the engine -- dockerd/containerd/runc is broken or down"
fi

verify_finish
