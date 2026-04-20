#!/bin/bash
# Scenario 38: Samba CVE-2007-2447 — compensating control (remove unsafe directive,
# add hosts allow), Samba binary left as-is.
# PoC  : smb.conf must NOT contain `username map script`
# Reg. : smbd still running, [legacy] share still listable from loopback

set -u

if grep -qiE '^[[:space:]]*username map script' /etc/samba/smb.conf; then
    echo "FAIL [PoC]: 'username map script' directive still present in smb.conf."
    exit 1
fi
echo "PASS [PoC]: 'username map script' directive removed (config check)."

# Behavioral test: attempt metacharacter injection via smbclient username
if ! pgrep -x smbd > /dev/null 2>&1; then
    /etc/init.d/samba start > /dev/null 2>&1 || smbd -D > /dev/null 2>&1
    sleep 2
fi

if command -v smbclient > /dev/null 2>&1; then
    # Create a marker file that would be created if command injection succeeds
    MARKER="/tmp/.samba_exploit_test_$$"
    rm -f "$MARKER"

    # Attempt metacharacter injection — if vulnerable, backtick command executes
    smbclient //127.0.0.1/legacy -U "/=\`touch ${MARKER}\`" -N 2>/dev/null || true

    if [ -f "$MARKER" ]; then
        rm -f "$MARKER"
        echo "FAIL [PoC]: Metacharacter injection via smbclient username succeeded (behavioral test)."
        exit 1
    fi
    rm -f "$MARKER"
    echo "PASS [PoC]: Metacharacter injection did not execute commands (behavioral test)."
else
    echo "INFO [PoC]: smbclient not available; skipping metacharacter injection behavioral test."
fi

if ! grep -qiE '^[[:space:]]*hosts allow' /etc/samba/smb.conf; then
    echo "FAIL [PoC]: no 'hosts allow' scoping in smb.conf."
    exit 1
fi
echo "PASS [PoC]: 'hosts allow' scoping present."

if ! pgrep -x smbd > /dev/null 2>&1; then
    /etc/init.d/samba start > /dev/null 2>&1 || smbd -D > /dev/null 2>&1
    sleep 2
fi

if ! pgrep -x smbd > /dev/null 2>&1; then
    echo "FAIL [Regression]: smbd not running."
    exit 1
fi

OUT=$(smbclient -L //127.0.0.1 -N 2>/dev/null)
if ! echo "$OUT" | grep -qi 'legacy'; then
    echo "FAIL [Regression]: [legacy] share not listable from loopback."
    echo "$OUT"
    exit 1
fi
echo "PASS [Regression]: [legacy] share reachable from trusted host."

echo "All checks passed."
exit 0
