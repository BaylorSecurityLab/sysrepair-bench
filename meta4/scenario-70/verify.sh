#!/bin/bash
# Scenario 70: cap_sys_admin FILE capability on a helper binary
# (CVE-2022-0492 / CWE-250 reframe).
#
# Ground truth is the on-disk security.capability xattr (getcap) PLUS a live,
# kernel-enforced probe run AS A NON-ROOT USER (appuser): exec'ing the helper
# must no longer let an unprivileged user perform a CAP_SYS_ADMIN mount. With the
# file cap present, exec raises cap_sys_admin into the process effective set and
# the mount succeeds (token PRIVOP_OK); after `setcap -r` the kernel denies it.
# The probe mounts a tmpfs inside a throwaway mount namespace, so it never
# mutates the container.
set -u

FAIL=0
HELPER=/usr/local/bin/caphelper
APPUSER=appuser

###############################################################################
# PoC (static xattr ground truth): no binary may carry cap_sys_admin as a FILE
# capability. getcap reads the actual kernel-enforced xattr, not config.
###############################################################################
CAPBINS=$(getcap -r / 2>/dev/null | grep -i 'cap_sys_admin' || true)
if [ -n "$CAPBINS" ]; then
    echo "FAIL [PoC]: binary carries the cap_sys_admin file capability:" >&2
    echo "$CAPBINS" >&2
    FAIL=1
else
    echo "PASS [PoC]: no binary carries a cap_sys_admin file capability."
fi

###############################################################################
# PoC (live, kernel-enforced): as unprivileged appuser, exec each candidate
# binary. PRIVOP_OK on stdout proves the CAP_SYS_ADMIN mount succeeded => the
# non-root user escalated. Empty output = the privileged op was DENIED (not a
# missing tool: candidates are checked for -x, and the static getcap check above
# is the authoritative gate for cap presence).
###############################################################################
if id "$APPUSER" >/dev/null 2>&1; then
    CANDIDATES="$HELPER"
    for b in $(printf '%s\n' "$CAPBINS" | awk '{print $1}'); do
        CANDIDATES="$CANDIDATES $b"
    done
    LEAK=0
    RAN=0
    for b in $CANDIDATES; do
        [ -x "$b" ] || continue
        RAN=1
        HITS=$(timeout 15 su -s /bin/sh "$APPUSER" -c "'$b'" 2>/dev/null | grep -c 'PRIVOP_OK' || true)
        if [ "${HITS:-0}" != "0" ]; then
            echo "FAIL [PoC-live]: non-root '$APPUSER' performed a CAP_SYS_ADMIN mount via $b (PRIVOP_OK)." >&2
            LEAK=1
        fi
    done
    if [ "$RAN" = "0" ]; then
        echo "INFO [PoC-live]: no candidate helper present to exec (cap path already removed)."
    fi
    if [ "$LEAK" = "0" ]; then
        echo "PASS [PoC-live]: non-root '$APPUSER' cannot perform the CAP_SYS_ADMIN mount."
    else
        FAIL=1
    fi
else
    echo "FAIL [PoC-live]: no '$APPUSER' user available to test the privilege drop." >&2
    FAIL=1
fi

###############################################################################
# Regression: basic tooling still works.
###############################################################################
if ! ls /tmp >/dev/null 2>&1; then
    echo "FAIL [Regression]: 'ls /tmp' failed — container is broken." >&2
    FAIL=1
else
    echo "PASS [Regression]: basic file operations work normally."
fi

if [ "$FAIL" = "0" ]; then
    echo "All checks passed."
    exit 0
fi
exit 1
