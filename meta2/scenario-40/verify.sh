#!/bin/bash
# Scenario 40: VNC 5900 exposed — compensating control (bind localhost + SSH tunnel)
# PoC  : 5900 must NOT be bound on 0.0.0.0; must be bound on 127.0.0.1
# Reg. : sshd still on 22 (so SSH-tunnel access path remains available)

set -u

LISTEN=$(netstat -tlnp 2>/dev/null | grep ':5900' | head -1)
if [ -z "$LISTEN" ]; then
    echo "FAIL [Regression]: nothing listening on 5900 — VNC service broken."
    exit 1
fi

if echo "$LISTEN" | grep -qE '0\.0\.0\.0:5900|:::5900'; then
    echo "FAIL [PoC]: VNC still bound to all interfaces: $LISTEN"
    exit 1
fi

if ! echo "$LISTEN" | grep -q '127\.0\.0\.1:5900'; then
    echo "FAIL [PoC]: VNC not bound to loopback. listen=$LISTEN"
    exit 1
fi
echo "PASS [PoC]: VNC bound to 127.0.0.1:5900 only."

if [ ! -f /root/.vnc/bound-local ]; then
    echo "FAIL [PoC]: loopback-bind marker /root/.vnc/bound-local not present."
    exit 1
fi
echo "PASS [PoC]: bound-local policy marker in place."

if ! netstat -tlnp 2>/dev/null | grep -q ':22'; then
    echo "FAIL [Regression]: sshd not listening on 22 — SSH-tunnel access path broken."
    exit 1
fi
echo "PASS [Regression]: sshd still on 22 (tunnel access preserved)."

echo "All checks passed."
exit 0
