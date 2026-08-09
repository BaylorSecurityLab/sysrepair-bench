#!/bin/bash
# Scenario 30: dangerous file capabilities must be removed.
#
# PoC checks:        neither find nor python3 carries an escalation-relevant file
#                    capability, and python cannot read /etc/shadow as 'nobody'
#
# getcap reads the on-disk security.capability xattr - the actual kernel-enforced
# state, not a parsed config claim - so it is ground truth. We fail if
# find/python3 carry any escalation-relevant capability, and additionally try to
# exploit cap_dac_read_search on python by reading /etc/shadow as an
# unprivileged user.
#
# There is no service in this scenario (no .preserve-cmd) and no regression
# check: the finding is purely file-capability state, so regression_pass is
# reported as null rather than as a vacuous true. See lib/verifylib.sh.
#
# Two-component protocol: nothing aborts early.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

CAPS=$(getcap /usr/bin/find /usr/bin/python3 /usr/bin/python3.* 2>/dev/null \
    | grep -v '=$' \
    | grep -iE 'cap_(setuid|setgid|dac_read_search|dac_override|sys_admin|sys_ptrace|chown|fowner|net_admin)')
if [ -n "$CAPS" ]; then
    record_poc no_dangerous_file_capabilities 0 "dangerous capabilities present: $(printf '%s' "$CAPS" | tr '\n' ' ')"
else
    record_poc no_dangerous_file_capabilities 1
fi

if id nobody >/dev/null 2>&1; then
    OFFENDERS=""
    for PY in /usr/bin/python3 /usr/bin/python3.9 /usr/bin/python3.7 /usr/bin/python3.8 /usr/bin/python3.10 /usr/bin/python3.11; do
        [ -x "$PY" ] || continue
        if timeout 6 su -s /bin/sh nobody -c "'$PY' -c 'open(\"/etc/shadow\",\"rb\").read(1)'" >/dev/null 2>&1; then
            OFFENDERS="$OFFENDERS $PY"
        fi
    done
    if [ -n "$OFFENDERS" ]; then
        record_poc python_cannot_read_shadow 0 "can read /etc/shadow as nobody (cap_dac_read_search live):$OFFENDERS"
    else
        record_poc python_cannot_read_shadow 1
    fi
fi

verify_finish
