#!/bin/bash
set -u
PK=/usr/bin/pkexec
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

SAFE=0
# Path A: setuid bit cleared
if [ -f "$PK" ] && [ ! -u "$PK" ]; then
    echo "PASS [PoC]: pkexec setuid bit cleared."
    SAFE=1
fi

# Path B: package upgraded
VER=$(dpkg-query -W -f='${Version}' policykit-1 2>/dev/null || true)
if [ -n "$VER" ] && ver_ge "$VER" "0.105-26ubuntu1.3"; then
    echo "PASS [PoC]: policykit-1 upgraded to $VER."
    SAFE=1
fi

[ "$SAFE" = "1" ] || { echo "FAIL [PoC]: pkexec setuid bit present and policykit-1 $VER vulnerable." >&2; exit 1; }

# PoC (behavioral): verify pkexec SUID status at runtime via stat
if [ -f "$PK" ]; then
    PERMS=$(stat -c '%a' "$PK" 2>/dev/null || true)
    if [ -n "$PERMS" ]; then
        # Check if SUID bit is set (4xxx)
        FIRST_DIGIT="${PERMS:0:1}"
        if [ "${#PERMS}" -eq 4 ] && [ "$FIRST_DIGIT" -ge 4 ] 2>/dev/null; then
            # SUID is set — only acceptable if pkg is upgraded
            if [ -z "$VER" ] || ! ver_ge "$VER" "0.105-26ubuntu1.3"; then
                echo "FAIL [PoC]: pkexec has SUID permissions ($PERMS) and pkg not upgraded." >&2
                exit 1
            fi
        fi
        echo "PASS [PoC]: pkexec runtime permissions are $PERMS."
    fi
fi

# Regression: pkexec binary still exists
[ -f "$PK" ] && { echo "PASS [Regression]: pkexec binary present."; exit 0; }
echo "FAIL [Regression]: pkexec binary missing." >&2; exit 1
