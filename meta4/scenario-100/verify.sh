#!/bin/bash
# Scenario 100: SaltStack 3000 — ClearFuncs Auth Bypass (CVE-2020-11651)
# Compensating Controls: iptables + publisher_acl
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

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
    if iptables -L INPUT -n 2>/dev/null | grep -qE 'DROP.*dpt:4505'; then
        record_poc iptables_drop_4505 1
    else
        record_poc iptables_drop_4505 0 "no iptables DROP rule found for port 4505"
    fi

    if iptables -L INPUT -n 2>/dev/null | grep -qE 'DROP.*dpt:4506'; then
        record_poc iptables_drop_4506 1
    else
        record_poc iptables_drop_4506 0 "no iptables DROP rule found for port 4506"
    fi
else
    echo "INFO [PoC iptables]: skipped (no CAP_NET_ADMIN)."
fi

###############################################################################
# PoC 2: publisher_acl must be configured in master config
###############################################################################

MASTER_CONF="/etc/salt/master"

if [ -f "$MASTER_CONF" ]; then
    record_poc master_conf_present 1
else
    record_poc master_conf_present 0 "Salt master config not found at $MASTER_CONF"
fi

if grep -qE '^\s*publisher_acl\s*:' "$MASTER_CONF" 2>/dev/null; then
    record_poc publisher_acl_configured 1
else
    record_poc publisher_acl_configured 0 "publisher_acl not found in $MASTER_CONF"
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

SM_OK=0
for i in 1 2 3 4 5 6; do
    if [ -n "$(listening_on 4506 || true)" ]; then
        SM_OK=1
        break
    fi
    sleep 3
done

if [ "$SM_OK" = "1" ]; then
    record_reg salt_master_listening 1 "salt-master is listening on 4506 (ret bus)"
else
    record_reg salt_master_listening 0 "salt-master is not listening on 4506 after remediation"
fi

verify_finish
