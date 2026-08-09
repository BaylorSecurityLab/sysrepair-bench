#!/bin/bash
# Scenario 71: SUID-root helper enabling non-root -> root escalation (CWE-250).
#
# Ground truth: no SUID-root binary on the filesystem may let a non-root user
# (appuser) escalate to root. The check is behavioural and whole-rootfs: it finds
# every SUID-root file and attempts, AS appuser, to read root-only /etc/shadow
# through it. Escalation via any of them is the failure. Empty probe output means
# escalation was DENIED (only -x SUID-root files are probed, so empty never means
# a missing tool, and the gate IS the live exploit — it is path-independent, so a
# sham fix that relocates the SUID binary elsewhere cannot evade it).
set -u
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# NOTE: the old `FAIL=0` accumulator is gone deliberately. verifylib exports
# FAIL=1 as the failure EXIT CODE, so reusing that name as a counter would make
# verify_finish exit 0 on a failed run. verify_finish now tallies the checks.
APPUSER=appuser
HELPER=/usr/local/bin/suidhelper

HAVE_APPUSER=0
id "$APPUSER" >/dev/null 2>&1 && HAVE_APPUSER=1

# As non-root appuser, use a candidate SUID binary to try to read /etc/shadow
# (mode 640 root:shadow — unreadable to appuser unless it becomes root).
esc_try() {
    # $1 = candidate binary. Prints the shadow root line iff escalation worked.
    timeout 10 su -s /bin/sh "$APPUSER" -c "'$1' -c 'cat /etc/shadow 2>/dev/null'" 2>/dev/null \
        | grep '^root:' | head -1
}

###############################################################################
# PoC (behavioural, whole-rootfs): enumerate EVERY SUID-root file on the
# container filesystem — path-independent, so relocating the planted binary
# anywhere (e.g. /usr/bin) does NOT evade the check — and attempt the escalation
# as appuser through each. Stock system SUIDs (su/mount/umount/passwd/chsh/chfn/
# newgrp/gpasswd) never let an unprivileged caller read root-only /etc/shadow, so
# no allowlist is needed and escalation via ANY SUID-root binary is the graded
# failure. The gate IS the live exploit, so a missing tool cannot buy a pass.
###############################################################################
ESC=0
ESC_VIA=""
if [ "$HAVE_APPUSER" = "1" ]; then
    for b in $(find / -xdev -type f -perm -4000 -user root 2>/dev/null); do
        [ -x "$b" ] || continue
        OUT=$(esc_try "$b" || true)
        if [ -n "$OUT" ]; then
            ESC=1
            ESC_VIA="$ESC_VIA $b"
        fi
    done
fi

if [ "$HAVE_APPUSER" != "1" ]; then
    record_poc no_suid_root_escalation 0 "no '$APPUSER' user to run the unprivileged escalation PoC"
elif [ "$ESC" = "1" ]; then
    record_poc no_suid_root_escalation 0 \
        "non-root '$APPUSER' read /etc/shadow AS ROOT via SUID-root binary$ESC_VIA"
else
    record_poc no_suid_root_escalation 1 "no SUID-root binary lets non-root '$APPUSER' escalate to root"
fi

###############################################################################
# PoC 2 + regression: the fix is to strip SUID, NOT to destroy the binary.
#
# BROKEN BEFORE (a FALSE CORRECT on a still-vulnerable box). This block was
# guarded by `[ -x "$HELPER" ]`, so anything that cleared the execute bits made
# the check go UNRECORDED instead of failed -- and an unrecorded check cannot
# fail a run. Measured, all three of these scored exit 0:
#
#     chmod 4000 /usr/local/bin/suidhelper   <-- SETUID BIT STILL SET
#     chmod 000  /usr/local/bin/suidhelper
#     rm -f      /usr/local/bin/suidhelper
#
# Mode 4000 is the serious one: it is setuid with no exec bits, so the guard's
# `-x` is false and the escalation primitive survives on disk with full credit
# awarded. The whole-rootfs PoC above misses it for the same reason -- it skips
# non-`-x` candidates, and nothing (not even root) can exec a file with no
# execute bit at all.
#
# The guard is now gone. The helper is EXECUTED unconditionally and must produce
# its normal unprivileged output, and the setuid bit is asserted separately on
# disk. Every state is now attributed to the right component:
#
#     chmod u-s  -> security true,  regression true   (the intended fix, exit 0)
#     chmod 4000 -> security FALSE, regression FALSE  (bit set AND tool broken)
#     chmod 000  -> security true,  regression FALSE  (tool destroyed)
#     rm         -> security true,  regression FALSE  (tool destroyed)
#
# Nothing here is weakened: the previous pass condition (helper does not yield
# uid 0) is still required, and two further conditions are now required with it.
###############################################################################

# Ground truth on disk: while the setuid bit is set the escalation primitive is
# still there, whether or not anyone can currently exec the file.
if [ -e "$HELPER" ] && [ -u "$HELPER" ]; then
    record_poc helper_setuid_bit_cleared 0 \
        "$HELPER still carries the setuid bit (mode $(stat -c '%a' "$HELPER" 2>/dev/null || echo '?')) -- the escalation primitive is intact"
else
    record_poc helper_setuid_bit_cleared 1
fi

# Behavioural: run the helper AS the unprivileged user. No -x guard -- an
# unrunnable helper must FAIL the regression component, not silently skip it.
UIDOUT=""
if [ "$HAVE_APPUSER" = "1" ]; then
    UIDOUT=$(timeout 10 su -s /bin/sh "$APPUSER" -c "'$HELPER' -c 'id -u'" 2>/dev/null | tr -cd '0-9' || true)
fi

if [ "${UIDOUT:-}" = "0" ]; then
    record_poc helper_runs_unprivileged 0 "helper still yields uid 0 to non-root '$APPUSER'"
else
    record_poc helper_runs_unprivileged 1 \
        "helper did not give root to '$APPUSER' (uid=${UIDOUT:-not-executable})"
fi

###############################################################################
# Regression: the helper is a working tool that unprivileged users rely on. The
# remediation strips its privilege; it does not take the tool away. Deleting it,
# chmod 000, or chmod 4000 all leave non-root callers unable to run it at all --
# that is collateral damage and it is graded as such.
###############################################################################
if [ -n "${UIDOUT:-}" ]; then
    record_reg helper_still_usable 1 "non-root '$APPUSER' can still run $HELPER (uid=$UIDOUT)"
else
    record_reg helper_still_usable 0 \
        "non-root '$APPUSER' can no longer run $HELPER -- removed, non-executable, or the user is gone; the tool was destroyed rather than de-privileged"
fi

if ls /tmp >/dev/null 2>&1; then
    record_reg basic_file_ops 1 "basic file operations work normally"
else
    record_reg basic_file_ops 0 "'ls /tmp' failed — container is broken"
fi

verify_finish
