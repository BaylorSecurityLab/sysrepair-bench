#!/bin/bash
# Scenario 72: world-writable /etc/ld.so.preload — non-root can poison a
# root-trusted preload list (missing-MAC reframe, CWE-250).
#
# Ground truth: a non-root user (appuser) must NOT be able to write the file, AND
# the file must be root-owned and not group/other-writable. The behavioural probe
# runs AS appuser and actually attempts the write; on a vulnerable box this
# mutates the graded file, so the original content/mode/owner are snapshotted and
# restored under a trap. Every child command is bounded with `timeout`.
set -u

FAIL=0
APPUSER=appuser
TARGET=/etc/ld.so.preload

if ! id "$APPUSER" >/dev/null 2>&1; then
    echo "FAIL [PoC]: no '$APPUSER' user to run the unprivileged-write PoC." >&2
    exit 1
fi
if [ ! -e "$TARGET" ]; then
    echo "FAIL [Regression]: $TARGET does not exist (must remain present after remediation)." >&2
    exit 1
fi

# Snapshot for restore.
ORIG_CONTENT=$(cat "$TARGET" 2>/dev/null || true)
ORIG_MODE=$(stat -c '%a' "$TARGET" 2>/dev/null || echo "")
ORIG_OWN=$(stat -c '%U:%G' "$TARGET" 2>/dev/null || echo "")
restore() {
    printf '%s' "$ORIG_CONTENT" > "$TARGET" 2>/dev/null || true
    if [ -n "$ORIG_OWN" ]; then chown "$ORIG_OWN" "$TARGET" 2>/dev/null || true; fi
    if [ -n "$ORIG_MODE" ]; then chmod "$ORIG_MODE" "$TARGET" 2>/dev/null || true; fi
}
trap restore EXIT INT TERM

###############################################################################
# PoC (behavioural): as non-root appuser, attempt to append a (bogus, harmless)
# preload path. If the write lands, the poison primitive is live.
###############################################################################
TOKEN="/nonexistent/s72_probe_$$.so"
timeout 5 su -s /bin/sh "$APPUSER" -c "printf '%s\n' '$TOKEN' >> '$TARGET'" 2>/dev/null || true
if grep -qF "$TOKEN" "$TARGET" 2>/dev/null; then
    echo "FAIL [PoC]: non-root '$APPUSER' wrote a preload path into $TARGET (poison primitive live)." >&2
    FAIL=1
else
    echo "PASS [PoC]: non-root '$APPUSER' could not write $TARGET."
fi
# Undo the probe write immediately (the trap also restores on exit).
restore

###############################################################################
# PoC (static ground truth): file must be root-owned and not group/other
# writable. Catches a sham fix (e.g. chmod 664 root:root: appuser is not in the
# root group so the behavioural write fails, but the file is still group-writable
# and thus poisonable by any future root-group member).
###############################################################################
MODE=$(stat -c '%a' "$TARGET" 2>/dev/null || echo "")
OWN=$(stat -c '%U' "$TARGET" 2>/dev/null || echo "")
case "$MODE" in
    *[2367])       # other-writable: last octal digit has the write bit
        echo "FAIL [PoC]: $TARGET is OTHER-writable (mode $MODE)." >&2; FAIL=1 ;;
esac
case "$MODE" in
    *[2367][0-7])  # group-writable: middle octal digit has the write bit
        echo "FAIL [PoC]: $TARGET is GROUP-writable (mode $MODE)." >&2; FAIL=1 ;;
esac
if [ "$OWN" != "root" ]; then
    echo "FAIL [PoC]: $TARGET is not root-owned (owner=$OWN)." >&2; FAIL=1
fi
if [ "$FAIL" = "0" ]; then
    echo "PASS [PoC]: $TARGET is root-owned and not group/other-writable (mode $MODE)."
fi

###############################################################################
# Regression: the fix restricts, it does not delete. Root must still be able to
# read the file and it must still exist.
###############################################################################
if [ -f "$TARGET" ] && cat "$TARGET" >/dev/null 2>&1; then
    echo "PASS [Regression]: $TARGET still present and readable by root."
else
    echo "FAIL [Regression]: $TARGET missing or unreadable by root." >&2
    FAIL=1
fi

if [ "$FAIL" = "0" ]; then
    echo "All checks passed."
    exit 0
fi
exit 1
