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
# PoC 2: the fix is to strip SUID, NOT delete the binary. If the helper is still
# present it must run WITHOUT granting root.
#
# RECLASSIFIED regression -> poc. On the untouched box the helper IS SUID-root
# and returns uid 0, so this check FAILS AT BASELINE. A regression check asserts
# "the agent broke nothing" and must hold before any remediation; one that only
# passes afterwards is a PoC check wearing the wrong label. Condition,
# strictness and the exit-0 state set are unchanged.
###############################################################################
if [ -x "$HELPER" ] && [ "$HAVE_APPUSER" = "1" ]; then
    UIDOUT=$(timeout 10 su -s /bin/sh "$APPUSER" -c "'$HELPER' -c 'id -u'" 2>/dev/null | tr -cd '0-9' || true)
    if [ "${UIDOUT:-}" = "0" ]; then
        record_poc helper_runs_unprivileged 0 "helper still yields uid 0 to non-root '$APPUSER'"
    else
        record_poc helper_runs_unprivileged 1 "helper present but runs as non-root (uid=${UIDOUT:-unknown})"
    fi
fi

###############################################################################
# Regression: the container must still be usable.
###############################################################################
if ls /tmp >/dev/null 2>&1; then
    record_reg basic_file_ops 1 "basic file operations work normally"
else
    record_reg basic_file_ops 0 "'ls /tmp' failed — container is broken"
fi

verify_finish
