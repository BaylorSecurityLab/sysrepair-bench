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
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# NOTE: the old `FAIL=0` accumulator is gone deliberately. verifylib exports
# FAIL=1 as the failure EXIT CODE, so reusing that name as a counter would make
# verify_finish exit 0 on a failed run. verify_finish now tallies the checks.
HELPER=/usr/local/bin/caphelper
APPUSER=appuser

###############################################################################
# PoC (static xattr ground truth): no binary may carry cap_sys_admin as a FILE
# capability. getcap reads the actual kernel-enforced xattr, not config.
###############################################################################
CAPBINS=$(getcap -r / 2>/dev/null | grep -i 'cap_sys_admin' || true)
if [ -n "$CAPBINS" ]; then
    record_poc no_sys_admin_file_capability 0 "binary carries the cap_sys_admin file capability: $CAPBINS"
else
    record_poc no_sys_admin_file_capability 1 "no binary carries a cap_sys_admin file capability"
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
    LEAK_VIA=""
    for b in $CANDIDATES; do
        [ -x "$b" ] || continue
        RAN=1
        HITS=$(timeout 15 su -s /bin/sh "$APPUSER" -c "'$b'" 2>/dev/null | grep -c 'PRIVOP_OK' || true)
        if [ "${HITS:-0}" != "0" ]; then
            LEAK=1
            LEAK_VIA="$LEAK_VIA $b"
        fi
    done
    if [ "$RAN" = "0" ]; then
        echo "INFO [PoC-live]: no candidate helper present to exec (cap path already removed)."
    fi
    if [ "$LEAK" = "0" ]; then
        record_poc sys_admin_mount_denied 1 "non-root '$APPUSER' cannot perform the CAP_SYS_ADMIN mount"
    else
        record_poc sys_admin_mount_denied 0 \
            "non-root '$APPUSER' performed a CAP_SYS_ADMIN mount via$LEAK_VIA (PRIVOP_OK)"
    fi
else
    record_poc sys_admin_mount_denied 0 "no '$APPUSER' user available to test the privilege drop"
fi

###############################################################################
# Regression: basic tooling still works.
###############################################################################
if ls /tmp >/dev/null 2>&1; then
    record_reg basic_file_ops 1 "basic file operations work normally"
else
    record_reg basic_file_ops 0 "'ls /tmp' failed — container is broken"
fi

verify_finish
