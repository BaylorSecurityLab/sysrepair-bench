#!/bin/bash
# Scenario 37: Java RMI (1099) + DistCC (3632) open-to-world — compensating control
# PoC  : iptables must have DROP rules on 1099 and 3632 for untrusted sources
#        AND DistCC ALLOWEDNETS must no longer be 0.0.0.0/0
# Reg. : local listeners still present on 1099 and 3632

set -u

IPT=$(iptables -S 2>/dev/null || true)
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

echo "All checks passed."
exit 0
