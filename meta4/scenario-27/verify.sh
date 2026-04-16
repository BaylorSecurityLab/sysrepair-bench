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

echo "PASS [PoC]: xz version is $XZ_VER (outside affected 5.6.0–5.6.1 range)."

# Also check liblzma.so — it must not be the 5.6.0/5.6.1 build
LIBLZMA=$(find /usr/lib /usr/local/lib -name 'liblzma.so.5*' -type f 2>/dev/null | head -1)
if [ -n "$LIBLZMA" ]; then
    LIB_VER=$(strings "$LIBLZMA" 2>/dev/null | grep -oE '5\.[0-9]+\.[0-9]+' | head -1)
    case "$LIB_VER" in
        5.6.0|5.6.1)
            echo "FAIL [PoC]: liblzma reports $LIB_VER — still in affected range." >&2
            exit 1
            ;;
    esac
    echo "PASS [PoC]: liblzma version string is $LIB_VER."
fi

# Regression: xz round-trip must work
RESULT=$(echo "sysrepair-test" | xz -z 2>/dev/null | xz -d 2>/dev/null)
if [ "$RESULT" = "sysrepair-test" ]; then
    echo "PASS [Regression]: xz compress/decompress round-trip works."
    exit 0
fi
echo "FAIL [Regression]: xz round-trip failed (got: '$RESULT')." >&2
exit 1
