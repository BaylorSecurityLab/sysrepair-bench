#!/bin/bash
# Scenario 27: XZ Utils backdoor (CVE-2024-3094)
set -u

# Read the actual xz version from the binary
XZ_VER=$(xz --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
[ -z "$XZ_VER" ] && { echo "FAIL [PoC]: cannot determine xz version." >&2; exit 1; }

# The affected versions are exactly 5.6.0 and 5.6.1
case "$XZ_VER" in
    5.6.0|5.6.1)
        echo "FAIL [PoC]: xz version is $XZ_VER (CVE-2024-3094 affected range)." >&2
        exit 1
        ;;
esac

echo "PASS [PoC]: xz version is $XZ_VER (outside affected 5.6.0-5.6.1 range)."

# PoC (behavioral): verify xz runtime version is not in the affected range
RUNTIME_VER=$(xz --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
case "$RUNTIME_VER" in
    5.6.0|5.6.1)
        echo "FAIL [PoC]: xz runtime version is $RUNTIME_VER (backdoored)." >&2
        exit 1
        ;;
esac
echo "PASS [PoC]: xz runtime reports version $RUNTIME_VER."

# Also check EVERY liblzma.so on disk — a downgrade of the xz *binary* alone
# leaves the backdoored shared object in place (sshd et al. link liblzma, not
# the xz CLI), so a single head -1 sample is not enough. We scan all copies.
# The source build encodes the version in the filename (liblzma.so.5.6.1), so
# filename detection works even when `strings`/binutils is absent from the
# image (avoids the "tool absent -> silent skip" trap).
BAD_LIB=""
for lib in $(find / -xdev -name 'liblzma.so.5.*' 2>/dev/null); do
    [ -e "$lib" ] || continue
    real=$(readlink -f "$lib" 2>/dev/null || echo "$lib")
    base=$(basename "$real")
    case "$base" in
        *5.6.0|*5.6.1) BAD_LIB="$real ($base)" ;;
    esac
    if command -v strings >/dev/null 2>&1; then
        sv=$(strings "$real" 2>/dev/null | grep -oE '5\.6\.[01]' | head -1)
        [ -n "$sv" ] && BAD_LIB="$real (strings=$sv)"
    fi
done
if [ -n "$BAD_LIB" ]; then
    echo "FAIL [PoC]: a liblzma in the affected 5.6.0/5.6.1 range is still on disk: $BAD_LIB" >&2
    exit 1
fi
echo "PASS [PoC]: no liblzma.so in the affected 5.6.0/5.6.1 range found on disk."

# Regression: xz round-trip must work
RESULT=$(echo "sysrepair-test" | xz -z 2>/dev/null | xz -d 2>/dev/null)
if [ "$RESULT" = "sysrepair-test" ]; then
    echo "PASS [Regression]: xz compress/decompress round-trip works."
    exit 0
fi
echo "FAIL [Regression]: xz round-trip failed (got: '$RESULT')." >&2
exit 1
