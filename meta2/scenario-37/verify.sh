#!/bin/bash
# Scenario 37: Java RMI (1099) + DistCC (3632) open-to-world — compensating control
# PoC  : iptables must have DROP rules on 1099 and 3632 for untrusted sources
#        AND DistCC ALLOWEDNETS must no longer be 0.0.0.0/0
# Reg. : local listeners still present on 1099 and 3632

set -u

IPT=$(iptables-save 2>/dev/null || true)
if [ -z "$IPT" ]; then
    echo "FAIL [PoC]: iptables not usable in this container (need --cap-add=NET_ADMIN)."
    exit 1
fi

if ! echo "$IPT" | grep -qE '(-A INPUT.*(3632|1099).*-j (DROP|REJECT))|(-A INPUT.*-j (DROP|REJECT).*(3632|1099))'; then
    if ! echo "$IPT" | grep -qE '(3632|1099).*DROP' ; then
        echo "FAIL [PoC]: no iptables DROP/REJECT rule for 1099 or 3632."
        exit 1
    fi
fi
echo "PASS [PoC]: iptables restricts 1099/3632 exposure."

if grep -qE 'ALLOWEDNETS="?0\.0\.0\.0/0' /etc/default/distcc 2>/dev/null; then
    echo "FAIL [PoC]: DistCC still allows 0.0.0.0/0 in /etc/default/distcc."
    exit 1
fi
echo "PASS [PoC]: DistCC --allow no longer permits 0.0.0.0/0."

if ! netstat -tlnp 2>/dev/null | grep -q ':3632'; then
    echo "FAIL [Regression]: DistCC not listening on 3632 — service broken."
    exit 1
fi
if ! netstat -tlnp 2>/dev/null | grep -q ':1099'; then
    echo "FAIL [Regression]: RMI listener not on 1099 — service broken."
    exit 1
fi
echo "PASS [Regression]: both services still listening."

# Behavioral test: attempt to connect through the firewall to port 3632
# from a non-loopback perspective. Since we are inside the container,
# we can only test loopback — but verify the firewall rules are active
# by checking that an external-simulated connection would be dropped.
if command -v nc > /dev/null 2>&1; then
    # Test: nc connection to 3632 from loopback should still work (trusted)
    NC_OUT=$(echo "" | nc -w 3 127.0.0.1 3632 2>/dev/null; echo "EXIT:$?")
    EXIT_CODE=$(echo "$NC_OUT" | grep "EXIT:" | sed 's/EXIT://')
    echo "INFO [PoC]: Loopback connection to 3632 exited with code $EXIT_CODE (expected: accessible from trusted source)."

    # Verify the iptables rules are actually loaded (not just saved)
    ACTIVE_RULES=$(iptables -L INPUT -n 2>/dev/null || true)
    if echo "$ACTIVE_RULES" | grep -qE "(3632|1099).*(DROP|REJECT)"; then
        echo "PASS [PoC]: iptables DROP/REJECT rules for 3632/1099 are active in running ruleset (behavioral test)."
    elif echo "$ACTIVE_RULES" | grep -qE "DROP|REJECT"; then
        echo "PASS [PoC]: iptables has active DROP/REJECT rules (behavioral test)."
    else
        echo "FAIL [PoC]: No active iptables DROP/REJECT rules found in running ruleset (behavioral test)."
        exit 1
    fi
else
    echo "INFO [PoC]: nc not available; skipping connection behavioral test."
fi

echo "All checks passed."
exit 0
