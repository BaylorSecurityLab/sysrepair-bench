#!/bin/bash
# Verification script for Scenario 22: Kernel ASLR disabled
# Exit 0 = every check passed, Exit 1 = at least one check failed
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "re-enabled ASLR but broke the system" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

echo "=== PoC Test: Checking if ASLR is disabled ==="

# Check sysctl.conf for the insecure value
CONF_ASLR=$(grep -E "^\s*kernel\.randomize_va_space\s*=" /etc/sysctl.conf | tail -1 | awk -F= '{print $2}' | tr -d ' ')

# Also try runtime value (may not work in all Docker configurations)
RUNTIME_ASLR=$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo "")

echo "Config file value: ${CONF_ASLR:-not set}"
echo "Runtime value: ${RUNTIME_ASLR:-unavailable}"

if [ "$CONF_ASLR" = "0" ]; then
    record_poc aslr_not_disabled_in_conf 0 "ASLR is disabled (randomize_va_space=0) in sysctl.conf"
else
    record_poc aslr_not_disabled_in_conf 1
fi

# Ensure the value is set to at least 1 (preferably 2)
if [ -z "$CONF_ASLR" ]; then
    # If the line was removed entirely, check if any value is set
    # No explicit setting means the kernel default (usually 2) applies
    record_poc aslr_conf_value_valid 1 "ASLR setting removed from sysctl.conf (kernel default applies)"
elif [ "$CONF_ASLR" -ge 1 ] 2>/dev/null; then
    record_poc aslr_conf_value_valid 1 "ASLR is enabled (randomize_va_space=$CONF_ASLR)"
else
    record_poc aslr_conf_value_valid 0 "ASLR value is invalid or zero"
fi

# ADDED: /etc/sysctl.conf is not the only file sysctl reads. A drop-in under
# /etc/sysctl.d/ that re-disables ASLR would previously have gone unnoticed.
DROPIN_BAD=$(grep -lE "^\s*kernel\.randomize_va_space\s*=\s*0\s*$" \
    /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf 2>/dev/null)
if [ -n "$DROPIN_BAD" ]; then
    record_poc no_sysctl_dropin_disables_aslr 0 "a sysctl drop-in still disables ASLR: $DROPIN_BAD"
else
    record_poc no_sysctl_dropin_disables_aslr 1
fi

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
        record_poc aslr_enabled_at_runtime 0 "/proc/sys is writable here and ASLR is still 0 at runtime"
    else
        record_poc aslr_enabled_at_runtime 1 "ASLR is $RUNTIME_ASLR_CHECK at runtime (/proc/sys is writable, so this is authoritative)"
    fi
else
    # Deliberately NOT recorded either way: the value is the host kernel's, so it
    # is evidence of nothing. The /etc/sysctl.conf checks above are authoritative.
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
    record_reg sysctl_conf_parses 0 "/etc/sysctl.conf no longer parses cleanly: $(echo "$SYSCTL_PARSE" | grep -iE 'invalid syntax|malformed line|unknown key' | head -3 | tr '\n' ' ')"
else
    record_reg sysctl_conf_parses 1 "/etc/sysctl.conf parses cleanly ($(grep -cvE '^\s*(#|$)' /etc/sysctl.conf) active settings)"
fi

# 2. sysctl must still be able to READ the key it was asked to harden.
if sysctl -n kernel.randomize_va_space > /dev/null 2>&1; then
    record_reg sysctl_reads_aslr_key 1
else
    record_reg sysctl_reads_aslr_key 0 "sysctl can no longer read kernel.randomize_va_space"
fi

# 3. Userland must still fork/exec correctly and procps must see real processes.
SPAWN=$(bash -c 'echo sysrepair-spawn-ok' 2>/dev/null)
PID1=$(ps -o comm= -p 1 2>/dev/null | tr -d ' ')
if [ "$SPAWN" != "sysrepair-spawn-ok" ] || [ -z "$PID1" ]; then
    record_reg fork_exec_and_ps_work 0 "process creation or process listing is broken (spawn='$SPAWN', pid1='$PID1')"
else
    record_reg fork_exec_and_ps_work 1 "fork/exec works and ps reports PID 1 as '$PID1'"
fi

# 4. ASLR must actually randomise: three separate processes must land their
#    stacks at three different addresses. (Only assertable when the effective
#    runtime value is >= 1; in this container that value comes from the host.)
if [ "$RUNTIME_ASLR_CHECK" != "unavailable" ] && [ "$RUNTIME_ASLR_CHECK" != "0" ]; then
    STACKS=$(for _ in 1 2 3 4; do
        bash -c "grep '\[stack\]' /proc/self/maps | cut -d- -f1"
    done | sort -u | wc -l)
    if [ "$STACKS" -lt 2 ]; then
        record_reg aslr_observably_randomises 0 "randomize_va_space=$RUNTIME_ASLR_CHECK but stack addresses are identical across processes"
    else
        record_reg aslr_observably_randomises 1 "address-space randomisation is observable ($STACKS distinct stack bases in 4 processes)"
    fi
else
    echo "NOTE: runtime randomize_va_space is '$RUNTIME_ASLR_CHECK'; skipping the observable-randomisation check"
fi

verify_finish
