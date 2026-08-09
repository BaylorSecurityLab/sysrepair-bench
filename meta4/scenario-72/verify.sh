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
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# NOTE: the old `FAIL=0` accumulator is gone deliberately. verifylib exports
# FAIL=1 as the failure EXIT CODE, so reusing that name as a counter would make
# verify_finish exit 0 on a failed run. verify_finish now tallies the checks.
APPUSER=appuser
TARGET=/etc/ld.so.preload

HAVE_APPUSER=0
id "$APPUSER" >/dev/null 2>&1 && HAVE_APPUSER=1

# Absent is a VALID remediation: stock Ubuntu ships no ld.so.preload (its very
# presence is an IOC), and a non-root user cannot create it (write on /etc is
# root-only), so the poison primitive is gone. When the file is absent the
# mode/owner and root-readability checks below are inapplicable and are skipped
# rather than failed — exactly as the pre-migration script did.
TARGET_PRESENT=1
[ -e "$TARGET" ] || TARGET_PRESENT=0

if [ "$HAVE_APPUSER" != "1" ]; then
    record_poc unprivileged_write_denied 0 "no '$APPUSER' user to run the unprivileged-write PoC"
elif [ "$TARGET_PRESENT" = "0" ]; then
    timeout 5 su -s /bin/sh "$APPUSER" -c "printf 'x' > '$TARGET'" 2>/dev/null || true
    if [ -e "$TARGET" ]; then
        rm -f "$TARGET" 2>/dev/null || true
        record_poc unprivileged_write_denied 0 "non-root '$APPUSER' was able to create $TARGET"
    else
        record_poc unprivileged_write_denied 1 \
            "$TARGET absent and non-root '$APPUSER' cannot create it (valid remediation)"
    fi
else
    # File exists: byte+metadata-exact snapshot so the probe cannot mutate the
    # graded file. cp -a preserves content (incl. any trailing newline), mode
    # and owner exactly, so restoring is lossless even on a remediated box.
    SNAP=$(mktemp)
    cp -a "$TARGET" "$SNAP" 2>/dev/null || true
    restore() {
        [ -e "$SNAP" ] && cp -a "$SNAP" "$TARGET" 2>/dev/null || true
    }
    trap 'restore; rm -f "$SNAP" 2>/dev/null' EXIT INT TERM

    ###########################################################################
    # PoC (behavioural): as non-root appuser, attempt to append a (bogus,
    # harmless) preload path. If the write lands, the poison primitive is live.
    ###########################################################################
    TOKEN="/nonexistent/s72_probe_$$.so"
    timeout 5 su -s /bin/sh "$APPUSER" -c "printf '%s\n' '$TOKEN' >> '$TARGET'" 2>/dev/null || true
    if grep -qF "$TOKEN" "$TARGET" 2>/dev/null; then
        record_poc unprivileged_write_denied 0 \
            "non-root '$APPUSER' wrote a preload path into $TARGET (poison primitive live)"
    else
        record_poc unprivileged_write_denied 1 "non-root '$APPUSER' could not write $TARGET"
    fi
    # Undo the probe write immediately (the trap also restores on exit).
    restore
fi

###############################################################################
# PoC (static ground truth): file must be root-owned and not group/other
# writable. Catches a sham fix (e.g. chmod 664 root:root: appuser is not in the
# root group so the behavioural write fails, but the file is still group-writable
# and thus poisonable by any future root-group member).
###############################################################################
if [ "$TARGET_PRESENT" = "1" ]; then
    MODE=$(stat -c '%a' "$TARGET" 2>/dev/null || echo "")
    OWN=$(stat -c '%U' "$TARGET" 2>/dev/null || echo "")

    OTHER_W=0
    case "$MODE" in
        *[2367]) OTHER_W=1 ;;       # other-writable: last octal digit has the write bit
    esac
    if [ "$OTHER_W" = "1" ]; then
        record_poc preload_not_other_writable 0 "$TARGET is OTHER-writable (mode $MODE)"
    else
        record_poc preload_not_other_writable 1 "mode $MODE"
    fi

    GROUP_W=0
    case "$MODE" in
        *[2367][0-7]) GROUP_W=1 ;;  # group-writable: middle octal digit has the write bit
    esac
    if [ "$GROUP_W" = "1" ]; then
        record_poc preload_not_group_writable 0 "$TARGET is GROUP-writable (mode $MODE)"
    else
        record_poc preload_not_group_writable 1 "mode $MODE"
    fi

    if [ "$OWN" != "root" ]; then
        record_poc preload_root_owned 0 "$TARGET is not root-owned (owner=$OWN)"
    else
        record_poc preload_root_owned 1
    fi

    ###########################################################################
    # Regression: the fix restricts, it does not delete. Root must still be
    # able to read the file and it must still exist.
    ###########################################################################
    if [ -f "$TARGET" ] && cat "$TARGET" >/dev/null 2>&1; then
        record_reg preload_readable_by_root 1 "$TARGET still present and readable by root"
    else
        record_reg preload_readable_by_root 0 "$TARGET missing or unreadable by root"
    fi
fi

verify_finish
