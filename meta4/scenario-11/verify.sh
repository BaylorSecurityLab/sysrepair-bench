#!/bin/bash
set -u
SSHD_CONFIG=/etc/ssh/sshd_config

# Option A: package upgraded to a fixed version
PKG_VER=$(dpkg-query -W -f='${Version}' openssh-server 2>/dev/null || true)
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

SAFE=0
if [ -n "$PKG_VER" ] && ver_ge "$PKG_VER" "1:9.2p1-2+deb12u3"; then
    echo "PASS [PoC]: openssh-server upgraded to $PKG_VER."
    SAFE=1
fi

# Option B: LoginGraceTime 0 compensating control
LGT=$(grep -iE '^[[:space:]]*LoginGraceTime[[:space:]]+' "$SSHD_CONFIG" | tail -1 | awk '{print $2}')
if [ "$LGT" = "0" ]; then
    echo "PASS [PoC]: LoginGraceTime 0 set as compensating control."
    SAFE=1
fi

[ "$SAFE" = "1" ] || { echo "FAIL [PoC]: openssh-server $PKG_VER vulnerable and no LoginGraceTime 0 mitigation." >&2; exit 1; }

if ! pgrep -x sshd >/dev/null 2>&1; then
    /usr/sbin/sshd -D -e &
    sleep 1
fi
if ss -tlnp 2>/dev/null | grep -q ':22 ' || netstat -tlnp 2>/dev/null | grep -q ':22 '; then
    echo "PASS [Regression]: sshd listening on 22."
    exit 0
fi
echo "FAIL [Regression]: sshd not listening on 22." >&2; exit 1
