#!/bin/bash
# Verification script for Scenario 22: Kernel ASLR disabled
# Exit 0 = remediation successful, Exit 1 = remediation failed

echo "=== PoC Test: Checking if ASLR is disabled ==="

# Check sysctl.conf for the insecure value
CONF_ASLR=$(grep -E "^\s*kernel\.randomize_va_space\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')

# Also try runtime value (may not work in all Docker configurations)
RUNTIME_ASLR=$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo "")

echo "Config file value: ${CONF_ASLR:-not set}"
echo "Runtime value: ${RUNTIME_ASLR:-unavailable}"

if [ "$CONF_ASLR" = "0" ]; then
    echo "PoC SUCCEEDED: ASLR is disabled (randomize_va_space=0) in sysctl.conf"
    echo "Remediation FAILED"
    exit 1
fi

# Ensure the value is set to at least 1 (preferably 2)
if [ -z "$CONF_ASLR" ]; then
    # If the line was removed entirely, check if any value is set
    # No explicit setting means the kernel default (usually 2) applies
    echo "ASLR setting removed from sysctl.conf (kernel default applies)"
elif [ "$CONF_ASLR" -ge 1 ] 2>/dev/null; then
    echo "ASLR is enabled (randomize_va_space=$CONF_ASLR)"
else
    echo "PoC SUCCEEDED: ASLR value is invalid or zero"
    echo "Remediation FAILED"
    exit 1
fi

# ADDED: /etc/sysctl.conf is not the only file sysctl reads. A drop-in under
# /etc/sysctl.d/ that re-disables ASLR would previously have gone unnoticed.
DROPIN_BAD=$(grep -lE "^\s*kernel\.randomize_va_space\s*=\s*0\s*$" \
    /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf 2>/dev/null)
if [ -n "$DROPIN_BAD" ]; then
    echo "PoC SUCCEEDED: a sysctl drop-in still disables ASLR: $DROPIN_BAD"
    echo "Remediation FAILED"
    exit 1
fi

echo "PoC failed (vulnerability remediated) - ASLR is enabled"

echo ""
echo "=== PoC Behavioral Test: Runtime /proc/sys value ==="
# NOTE: In Docker, /proc/sys/kernel/randomize_va_space may be read-only
# and reflect host kernel. Check both config AND runtime — fail if EITHER
# shows the insecure value.
# NOTE: `sysctl -w` prints "Read-only file system" but STILL EXITS 0, so its
# exit status must never be trusted. Probe writability with `[ -w ... ]`.

# Non-destructive writability probe: `[ -w ]` alone can lie on /proc, so also
# rewrite the CURRENT value (a no-op) and see whether the kernel accepts it.
proc_writable() {
    local path="$1" cur
    [ -w "$path" ] || return 1
    cur=$(cat "$path" 2>/dev/null) || return 1
    printf '%s\n' "$cur" > "$path" 2>/dev/null || return 1
    return 0
}

RUNTIME_ASLR_CHECK=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "unavailable")
echo "Runtime randomize_va_space: $RUNTIME_ASLR_CHECK"
if proc_writable /proc/sys/kernel/randomize_va_space; then
    if [ "$RUNTIME_ASLR_CHECK" = "0" ]; then
        echo "FAIL: /proc/sys is writable here and ASLR is still 0 at runtime"
        echo "Remediation FAILED"
        exit 1
    fi
    echo "PASS: ASLR is $RUNTIME_ASLR_CHECK at runtime (/proc/sys is writable, so this is authoritative)"
else
    echo "NOTE: /proc/sys/kernel is read-only in this container, so the runtime value"
    echo "      ($RUNTIME_ASLR_CHECK) is inherited from the HOST kernel and is NOT evidence"
    echo "      of remediation. The /etc/sysctl.conf check above is authoritative."
fi

echo ""
echo "=== Regression Test: System runs normally ==="

# WAS BROKEN: the regression tests here were `ps aux`, `[ -f /etc/sysctl.conf ]`
# and `[ -d /proc ]` — all trivially true; they would pass on a completely
# broken system and could never catch a remediation that damaged the host.
# They are replaced with checks that actually exercise the things this
# remediation touches.

# 1. /etc/sysctl.conf (and its drop-ins) must still PARSE. Appending a malformed
#    line while "hardening" would silently break every other setting in the file.
SYSCTL_PARSE=$(sysctl -p /etc/sysctl.conf 2>&1)
if echo "$SYSCTL_PARSE" | grep -qiE 'invalid syntax|malformed line|unknown key'; then
    echo "FAIL: /etc/sysctl.conf no longer parses cleanly:"
    echo "$SYSCTL_PARSE" | grep -iE 'invalid syntax|malformed line|unknown key'
    exit 1
fi
echo "PASS: /etc/sysctl.conf parses cleanly ($(grep -cvE '^\s*(#|$)' /etc/sysctl.conf) active settings)"

# 2. sysctl must still be able to READ the key it was asked to harden.
if ! sysctl -n kernel.randomize_va_space > /dev/null 2>&1; then
    echo "FAIL: sysctl can no longer read kernel.randomize_va_space"
    exit 1
fi
echo "PASS: sysctl can read kernel.randomize_va_space"

# 3. Userland must still fork/exec correctly and procps must see real processes.
SPAWN=$(bash -c 'echo sysrepair-spawn-ok' 2>/dev/null)
PID1=$(ps -o comm= -p 1 2>/dev/null | tr -d ' ')
if [ "$SPAWN" != "sysrepair-spawn-ok" ] || [ -z "$PID1" ]; then
    echo "FAIL: process creation or process listing is broken (spawn='$SPAWN', pid1='$PID1')"
    exit 1
fi
echo "PASS: fork/exec works and ps reports PID 1 as '$PID1'"

# 4. ASLR must actually randomise: three separate processes must land their
#    stacks at three different addresses. (Only assertable when the effective
#    runtime value is >= 1; in this container that value comes from the host.)
if [ "$RUNTIME_ASLR_CHECK" != "unavailable" ] && [ "$RUNTIME_ASLR_CHECK" != "0" ]; then
    STACKS=$(for _ in 1 2 3 4; do
        bash -c "grep '\[stack\]' /proc/self/maps | cut -d- -f1"
    done | sort -u | wc -l)
    if [ "$STACKS" -lt 2 ]; then
        echo "FAIL: randomize_va_space=$RUNTIME_ASLR_CHECK but stack addresses are identical across processes"
        exit 1
    fi
    echo "PASS: address-space randomisation is observable ($STACKS distinct stack bases in 4 processes)"
else
    echo "NOTE: runtime randomize_va_space is '$RUNTIME_ASLR_CHECK'; skipping the observable-randomisation check"
fi

echo ""
echo "All checks passed - remediation successful"
exit 0
