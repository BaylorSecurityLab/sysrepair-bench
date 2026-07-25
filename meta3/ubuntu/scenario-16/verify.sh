#!/bin/bash
# Verification for meta3-ubuntu/scenario-16: MySQL 5.5 bound to 0.0.0.0 --
# compensating control (restrict bind-address + hosts.allow/deny allowlist).
# Exit 0 = remediated (PASS), Exit 1 = vulnerable or broken.
#
# DYNAMIC: the runtime bind is read from the LIVE listener via /proc/net/tcp
# (state 0A, HEX ip:port; 0CEA == 3306). bind-address is read once at startup,
# so "edited my.cnf but did not restart mysqld" correctly FAILS. `ss` is NOT
# relied on -- it prints "*:3306" for an all-interfaces bind, never a literal
# 0.0.0.0.
set -u
MY_CNF=/etc/mysql/my.cnf
HOSTS_ALLOW=/etc/hosts.allow
HOSTS_DENY=/etc/hosts.deny
PORT_HEX=0CEA          # 3306

bound_any() {
    awk -v p=":$PORT_HEX" '$4=="0A" && $2=="00000000"p {f=1} END{exit !f}' /proc/net/tcp 2>/dev/null && return 0
    awk -v p=":$PORT_HEX" '$4=="0A" && $2=="00000000000000000000000000000000"p {f=1} END{exit !f}' /proc/net/tcp6 2>/dev/null && return 0
    return 1
}
present() {
    awk -v p=":$PORT_HEX" '$4=="0A" && $2 ~ p"$" {f=1} END{exit !f}' /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

###############################################################################
# PoC 1 (RUNTIME): port 3306 must NOT be bound to all interfaces.
###############################################################################
if bound_any; then
    echo "FAIL [PoC-Runtime]: port 3306 is bound to 0.0.0.0 / :: at runtime -- MySQL reachable on all interfaces (restart after editing my.cnf)." >&2
    exit 1
fi
echo "PASS [PoC-Runtime]: port 3306 is not bound to all interfaces."

# Config corroboration: bind-address must not be 0.0.0.0.
BIND=$(grep -iE '^\s*bind-address\s*=' "$MY_CNF" 2>/dev/null | tail -1 | sed 's/.*=\s*//' | tr -d ' \t')
if [ "$BIND" = "0.0.0.0" ] || [ -z "$BIND" ]; then
    echo "FAIL [PoC-Config]: bind-address in $MY_CNF is '${BIND:-<missing>}' (must be a restricted address)." >&2
    exit 1
fi
echo "PASS [PoC-Config]: bind-address = $BIND."

###############################################################################
# PoC 2: TCP-wrappers allowlist -- deny-all default plus an explicit allow.
###############################################################################
if ! grep -qiE '^\s*mysqld\s*:\s*ALL' "$HOSTS_DENY" 2>/dev/null; then
    echo "FAIL [PoC-HostsDeny]: $HOSTS_DENY does not contain 'mysqld: ALL'." >&2
    exit 1
fi
if ! grep -iE '^\s*mysqld\s*:' "$HOSTS_ALLOW" 2>/dev/null | grep -qv 'ALL'; then
    echo "FAIL [PoC-HostsAllow]: $HOSTS_ALLOW has no specific 'mysqld:' allow entry." >&2
    exit 1
fi
echo "PASS [PoC-Wrappers]: hosts.deny denies mysqld and hosts.allow has a specific allow."

###############################################################################
# Regression: mysqld up + trusted_user can query over loopback.
###############################################################################
if ! present; then
    echo "FAIL [Regression]: nothing LISTENing on 3306 -- MySQL is down." >&2
    exit 1
fi
OK=$(timeout 12 mysql -h 127.0.0.1 -u trusted_user -pTrustedP@ss1 -N -e 'SELECT 1;' 2>/dev/null | tr -d ' ')
if [ "$OK" = "1" ]; then
    echo "PASS [Regression]: trusted_user connected over 127.0.0.1 and ran a query."
else
    echo "FAIL [Regression]: trusted_user could not query MySQL on 127.0.0.1 (remote-trusted path broken)." >&2
    exit 1
fi

echo "All checks passed."
exit 0
