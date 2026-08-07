#!/bin/bash
# Scenario 69: file capability cap_sys_ptrace on a helper binary (CWE-250).
#
# Ground truth is the on-disk security.capability xattr (getcap) PLUS a live,
# kernel-enforced probe: an unprivileged user (nobody) must NOT be able to use
# any binary to read a root-owned process's memory map (/proc/1/maps). With the
# file cap present, exec'ing the binary raises cap_sys_ptrace into the process's
# effective set and the read succeeds; after `setcap -r` the kernel denies it.
# The probe only READS /proc — it never mutates the container.
set -u
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# NOTE: the old `FAIL=0` accumulator is gone deliberately. verifylib exports
# FAIL=1 as the failure EXIT CODE, so reusing that name as a counter would make
# verify_finish exit 0 on a failed run. verify_finish now tallies the checks.

###############################################################################
# PoC (static, xattr ground truth): no binary may carry cap_sys_ptrace as a
# file capability. getcap reads the actual kernel-enforced xattr, not config.
###############################################################################
CAPBINS=$(getcap -r / 2>/dev/null | grep -i 'cap_sys_ptrace' || true)
if [ -n "$CAPBINS" ]; then
    record_poc no_ptrace_file_capability 0 "binary carries the cap_sys_ptrace file capability: $CAPBINS"
else
    record_poc no_ptrace_file_capability 1 "no binary carries a cap_sys_ptrace file capability"
fi

###############################################################################
# PoC (live, kernel-enforced): as unprivileged 'nobody', try to read a
# root-owned process's memory map via each candidate binary. Success proves the
# cap is live and exploitable. /proc/1/maps requires PTRACE_MODE_READ on the
# target; without cap_sys_ptrace the kernel returns EACCES (empty output).
###############################################################################
probe_maps() {
    # $1 = binary path. Prints the first map line iff the read is permitted.
    timeout 6 su -s /bin/sh nobody -c "'$1' /proc/1/maps 2>/dev/null" 2>/dev/null | head -1
}

if id nobody >/dev/null 2>&1; then
    CANDIDATES="/opt/ptrace-helper"
    for b in $(printf '%s\n' "$CAPBINS" | awk '{print $1}'); do
        CANDIDATES="$CANDIDATES $b"
    done
    LEAK=0
    LEAK_VIA=""
    for b in $CANDIDATES; do
        [ -x "$b" ] || continue
        OUT=$(probe_maps "$b" || true)
        if [ -n "$OUT" ]; then
            LEAK=1
            LEAK_VIA="$LEAK_VIA $b"
        fi
    done
    if [ "$LEAK" = "0" ]; then
        record_poc ptrace_denied_to_nobody 1 "unprivileged 'nobody' cannot read /proc/1/maps (ptrace denied)"
    else
        record_poc ptrace_denied_to_nobody 0 \
            "unprivileged 'nobody' read /proc/1/maps via$LEAK_VIA (cap_sys_ptrace is live)"
    fi
else
    record_poc ptrace_denied_to_nobody 0 "no 'nobody' user available to test the privilege drop"
fi

###############################################################################
# Regression: basic tooling still works, and the helper (if kept) still works
# as an ordinary utility (reading a world-readable file must succeed).
###############################################################################
if ls /tmp >/dev/null 2>&1; then
    record_reg basic_file_ops 1 "basic file operations work normally"
else
    record_reg basic_file_ops 0 "'ls /tmp' failed — container is broken"
fi

if [ -x /opt/ptrace-helper ]; then
    if /opt/ptrace-helper /etc/hostname >/dev/null 2>&1; then
        record_reg helper_still_usable 1 "helper still functions as a normal utility"
    else
        record_reg helper_still_usable 0 "/opt/ptrace-helper cannot read a normal file — broken"
    fi
fi

verify_finish
