#!/bin/bash
# Scenario 100: SaltStack 3000 — ClearFuncs Auth Bypass (CVE-2020-11651)
# Compensating Controls: iptables + publisher_acl
set -u

###############################################################################
# Pre-check: CAP_NET_ADMIN required for iptables verification
###############################################################################

if ! iptables -L INPUT -n 2>/dev/null | grep -q 'Chain INPUT'; then
    echo "SKIP [iptables]: CAP_NET_ADMIN not available — skipping iptables checks." >&2
    SKIP_IPTABLES=1
else
    SKIP_IPTABLES=0
fi

###############################################################################
# PoC 1: iptables DROP rules must exist for ports 4505 and 4506
###############################################################################

if [ "$SKIP_IPTABLES" = "0" ]; then
    if iptables -L INPUT -n | grep -qE 'DROP.*dpt:4505'; then
        echo "PASS [PoC]: iptables DROP rule present for port 4505."
    else
        echo "FAIL [PoC]: No iptables DROP rule found for port 4505." >&2
        exit 1
    fi

    if iptables -L INPUT -n | grep -qE 'DROP.*dpt:4506'; then
        echo "PASS [PoC]: iptables DROP rule present for port 4506."
    else
        echo "FAIL [PoC]: No iptables DROP rule found for port 4506." >&2
        exit 1
    fi
else
    echo "INFO [PoC iptables]: skipped (no CAP_NET_ADMIN)."
fi

###############################################################################
# PoC 2: publisher_acl must be configured in master config
###############################################################################

MASTER_CONF="/etc/salt/master"

if [ ! -f "$MASTER_CONF" ]; then
    echo "FAIL [PoC]: Salt master config not found at $MASTER_CONF." >&2
    exit 1
fi

if grep -qE '^\s*publisher_acl\s*:' "$MASTER_CONF"; then
    echo "PASS [PoC]: publisher_acl is configured in $MASTER_CONF."
else
    echo "FAIL [PoC]: publisher_acl not found in $MASTER_CONF." >&2
    exit 1
fi

###############################################################################
# Regression: salt-master process must be running
###############################################################################

for i in 1 2 3 4 5; do
    if pgrep -x salt-master > /dev/null 2>&1; then
        echo "PASS [Regression]: salt-master process is running."
        exit 0
    fi
    sleep 2
done

echo "FAIL [Regression]: salt-master process is not running." >&2
exit 1
