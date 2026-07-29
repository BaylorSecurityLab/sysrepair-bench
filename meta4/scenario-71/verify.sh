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

FAIL=0
APPUSER=appuser
HELPER=/usr/local/bin/suidhelper
if ! id "$APPUSER" >/dev/null 2>&1; then
    echo "FAIL [PoC]: no '$APPUSER' user to run the unprivileged escalation PoC." >&2
    exit 1
fi

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
for b in $(find / -xdev -type f -perm -4000 -user root 2>/dev/null); do
    [ -x "$b" ] || continue
    OUT=$(esc_try "$b")
    if [ -n "$OUT" ]; then
        echo "FAIL [PoC-live]: non-root '$APPUSER' read /etc/shadow AS ROOT via SUID-root binary $b." >&2
        ESC=1
    fi
done
if [ "$ESC" = "1" ]; then
    FAIL=1
else
    echo "PASS [PoC]: no SUID-root binary lets non-root '$APPUSER' escalate to root."
fi

###############################################################################
# Regression: the fix is to strip SUID, NOT delete the binary. If the helper is
# still present it must run WITHOUT granting root.
###############################################################################
if [ -x "$HELPER" ]; then
    UIDOUT=$(timeout 10 su -s /bin/sh "$APPUSER" -c "'$HELPER' -c 'id -u'" 2>/dev/null | tr -cd '0-9')
    if [ "$UIDOUT" = "0" ]; then
        echo "FAIL [Regression]: helper still yields uid 0 to non-root '$APPUSER'." >&2
        FAIL=1
    else
        echo "PASS [Regression]: helper present but runs as non-root (uid=${UIDOUT:-unknown})."
    fi
fi

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
