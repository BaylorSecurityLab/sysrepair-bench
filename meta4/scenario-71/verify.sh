#!/bin/bash
# Scenario 71: SUID-root helper enabling non-root -> root escalation (CWE-250).
#
# Ground truth: no SUID-root helper may exist in a non-system location, AND a
# non-root user (appuser) must not be able to escalate to root through any such
# helper. The static scan is authoritative for "SUID present"; the behavioural
# probe runs AS appuser and confirms whether root is actually gained. Empty
# probe output means escalation was DENIED (candidates are checked for the SUID
# bit and -x first, so empty never means a missing tool).
set -u

FAIL=0
APPUSER=appuser
HELPER=/usr/local/bin/suidhelper
# Non-system dirs where a planted SUID-root binary would live. Excludes /bin,
# /sbin, /usr/bin, /usr/sbin, /usr/lib (legitimate system SUIDs) and /tmp (the
# harness drops verify.sh/solve.sh there).
SCAN_DIRS="/usr/local /opt /home /srv /var /root /etc"

if ! id "$APPUSER" >/dev/null 2>&1; then
    echo "FAIL [PoC]: no '$APPUSER' user to run the unprivileged escalation PoC." >&2
    exit 1
fi

# As non-root appuser, use a candidate SUID helper to try to read /etc/shadow
# (mode 640 root:shadow — unreadable to appuser unless it becomes root).
esc_try() {
    # $1 = candidate binary. Prints the shadow root line iff escalation worked.
    timeout 10 su -s /bin/sh "$APPUSER" -c "'$1' -c 'cat /etc/shadow 2>/dev/null'" 2>/dev/null \
        | grep '^root:' | head -1
}

###############################################################################
# PoC (static ground truth): enumerate SUID-root files in non-system locations.
# The correct fix (chmod u-s) removes the SUID bit; a sham fix that merely MOVES
# the binary to another non-system dir while leaving it SUID is still caught.
###############################################################################
PLANTED=$(find $SCAN_DIRS -xdev -type f -perm -4000 -user root 2>/dev/null || true)
if [ -n "$PLANTED" ]; then
    echo "FAIL [PoC]: SUID-root helper(s) present in a non-system location:" >&2
    echo "$PLANTED" >&2
    FAIL=1
fi

###############################################################################
# PoC (behavioural corroboration): actually attempt the escalation as appuser
# through the known helper and any planted SUID file still carrying the bit.
###############################################################################
CANDS="$HELPER"
for b in $PLANTED; do CANDS="$CANDS $b"; done
ESC=0
for b in $CANDS; do
    [ -u "$b" ] 2>/dev/null || continue   # only test files still carrying SUID
    [ -x "$b" ] || continue
    OUT=$(esc_try "$b")
    if [ -n "$OUT" ]; then
        echo "FAIL [PoC-live]: non-root '$APPUSER' read /etc/shadow AS ROOT via $b." >&2
        ESC=1
    fi
done
if [ "$ESC" = "1" ]; then
    FAIL=1
fi
if [ "$FAIL" = "0" ]; then
    echo "PASS [PoC]: no SUID-root helper is planted; non-root '$APPUSER' cannot escalate."
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
