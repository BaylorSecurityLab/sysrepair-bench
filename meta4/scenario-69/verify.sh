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

FAIL=0

###############################################################################
# PoC (static, xattr ground truth): no binary may carry cap_sys_ptrace as a
# file capability. getcap reads the actual kernel-enforced xattr, not config.
###############################################################################
CAPBINS=$(getcap -r / 2>/dev/null | grep -i 'cap_sys_ptrace' || true)
if [ -n "$CAPBINS" ]; then
    echo "FAIL [PoC]: binary carries the cap_sys_ptrace file capability:" >&2
    echo "$CAPBINS" >&2
    FAIL=1
else
    echo "PASS [PoC]: no binary carries a cap_sys_ptrace file capability."
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
    for b in $CANDIDATES; do
        [ -x "$b" ] || continue
        OUT=$(probe_maps "$b")
        if [ -n "$OUT" ]; then
            echo "FAIL [PoC-live]: unprivileged 'nobody' read /proc/1/maps via $b" \
                 "(cap_sys_ptrace is live): $OUT" >&2
            LEAK=1
        fi
    done
    if [ "$LEAK" = "0" ]; then
        echo "PASS [PoC-live]: unprivileged 'nobody' cannot read /proc/1/maps (ptrace denied)."
    else
        FAIL=1
    fi
else
    echo "FAIL [PoC-live]: no 'nobody' user available to test the privilege drop." >&2
    FAIL=1
fi

###############################################################################
# Regression: basic tooling still works, and the helper (if kept) still works
# as an ordinary utility (reading a world-readable file must succeed).
###############################################################################
if ! ls /tmp >/dev/null 2>&1; then
    echo "FAIL [Regression]: 'ls /tmp' failed — container is broken." >&2
    FAIL=1
else
    echo "PASS [Regression]: basic file operations work normally."
fi

if [ -x /opt/ptrace-helper ]; then
    if ! /opt/ptrace-helper /etc/hostname >/dev/null 2>&1; then
        echo "FAIL [Regression]: /opt/ptrace-helper cannot read a normal file — broken." >&2
        FAIL=1
    else
        echo "PASS [Regression]: helper still functions as a normal utility."
    fi
fi

if [ "$FAIL" = "0" ]; then
    echo "All checks passed."
    exit 0
fi
exit 1
