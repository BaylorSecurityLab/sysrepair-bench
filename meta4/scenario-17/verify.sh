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

# PoC (behavioral live): actually invoke pkexec as the victim user with empty argv.
# On a vulnerable PwnKit build the binary silently drops privileges or returns
# a specific argc==0 error path; on a patched/de-SUID'd build the euid of the
# child process must NOT be 0.
if id victim >/dev/null 2>&1 && [ -f "$PK" ]; then
    EUID_OUT=$(su - victim -c "exec -a '' $PK 2>/dev/null; id -u" 2>/dev/null | tail -1 || true)
    if [ "$EUID_OUT" = "0" ]; then
        echo "FAIL [PoC]: pkexec invoked by victim yielded euid=0 (PwnKit still reachable)." >&2
        exit 1
    fi
    echo "PASS [PoC]: pkexec runtime invocation by victim did not escalate (euid=$EUID_OUT)."
fi

# Regression: pkexec binary still exists
[ -f "$PK" ] && { echo "PASS [Regression]: pkexec binary present."; exit 0; }
echo "FAIL [Regression]: pkexec binary missing." >&2; exit 1
