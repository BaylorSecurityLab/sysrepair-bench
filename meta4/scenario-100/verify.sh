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
# Regression: salt-master must still be LISTENING on its ZeroMQ ret bus (4506).
# (pgrep/pgrep -x is not available on this slim base, and salt does not set a
# proctitle, so match on the live listening socket via /proc/net/tcp instead.
# The iptables DROP rules filter INPUT - they do NOT remove the LISTEN socket -
# so a correctly-restarted master is still visible here.)
###############################################################################

listening_on() {
    # $1 = decimal port; prints "yes" if a socket is in LISTEN (state 0A).
    awk 'NR>1 && $4=="0A"{print $2}' /proc/net/tcp /proc/net/tcp6 2>/dev/null \
        | sed 's/.*://' \
        | while read -r hexport; do
            [ "$((16#$hexport))" = "$1" ] && echo yes && break
        done
}

for i in 1 2 3 4 5 6; do
    if [ -n "$(listening_on 4506)" ]; then
        echo "PASS [Regression]: salt-master is listening on 4506 (ret bus)."
        exit 0
    fi
    sleep 3
done

echo "FAIL [Regression]: salt-master is not listening on 4506 after remediation." >&2
exit 1
