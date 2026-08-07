#!/bin/bash
# Scenario 27: XZ Utils backdoor (CVE-2024-3094)
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "removed the backdoored xz but broke compression" is reported
# as security_pass=true / regression_pass=false rather than collapsing into a
# bare exit 1. See lib/verifylib.sh.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# Read the actual xz version from the binary
XZ_VER=$(xz --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
if [ -z "$XZ_VER" ]; then
    record_poc xz_version_not_affected 0 "cannot determine xz version"
else
    # The affected versions are exactly 5.6.0 and 5.6.1
    case "$XZ_VER" in
        5.6.0|5.6.1)
            record_poc xz_version_not_affected 0 "xz version is $XZ_VER (CVE-2024-3094 affected range)"
            ;;
        *)
            record_poc xz_version_not_affected 1 "xz version is $XZ_VER (outside affected 5.6.0-5.6.1 range)"
            ;;
    esac
fi

###############################################################################
# PoC (behavioral): verify xz runtime version is not in the affected range.
###############################################################################
RUNTIME_VER=$(xz --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
case "$RUNTIME_VER" in
    5.6.0|5.6.1)
        record_poc xz_runtime_not_backdoored 0 "xz runtime version is $RUNTIME_VER (backdoored)"
        ;;
    *)
        record_poc xz_runtime_not_backdoored 1 "xz runtime reports version ${RUNTIME_VER:-unknown}"
        ;;
esac

###############################################################################
# Also check EVERY liblzma.so on disk — a downgrade of the xz *binary* alone
# leaves the backdoored shared object in place (sshd et al. link liblzma, not
# the xz CLI), so a single head -1 sample is not enough. We scan all copies.
# The source build encodes the version in the filename (liblzma.so.5.6.1), so
# filename detection works even when `strings`/binutils is absent from the
# image (avoids the "tool absent -> silent skip" trap).
###############################################################################
BAD_LIB=""
for lib in $(find / -xdev -name 'liblzma.so.5.*' 2>/dev/null || true); do
    [ -e "$lib" ] || continue
    real=$(readlink -f "$lib" 2>/dev/null || echo "$lib")
    base=$(basename "$real")
    case "$base" in
        *5.6.0|*5.6.1) BAD_LIB="$real ($base)" ;;
    esac
    if command -v strings >/dev/null 2>&1; then
        sv=$(strings "$real" 2>/dev/null | grep -oE '5\.6\.[01]' | head -1 || true)
        [ -n "$sv" ] && BAD_LIB="$real (strings=$sv)"
    fi
done
if [ -n "$BAD_LIB" ]; then
    record_poc liblzma_not_backdoored 0 "a liblzma in the affected 5.6.0/5.6.1 range is still on disk: $BAD_LIB"
else
    record_poc liblzma_not_backdoored 1
fi

###############################################################################
# Regression: xz round-trip must work.
###############################################################################
RESULT=$(echo "sysrepair-test" | xz -z 2>/dev/null | xz -d 2>/dev/null || true)
if [ "$RESULT" = "sysrepair-test" ]; then
    record_reg xz_roundtrip 1
else
    record_reg xz_roundtrip 0 "xz round-trip failed (got: '$RESULT')"
fi

verify_finish
