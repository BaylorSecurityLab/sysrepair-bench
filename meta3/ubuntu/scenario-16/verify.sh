#!/bin/bash
# Verification for meta3-ubuntu/scenario-16: MySQL 5.5 bound to 0.0.0.0 --
# compensating control (restrict bind-address + hosts.allow/deny allowlist).
# Exit 0 = every check passed, Exit 1 = at least one check failed.
#
# DYNAMIC: the runtime bind is read from the LIVE listener via /proc/net/tcp
# (state 0A, HEX ip:port; 0CEA == 3306). bind-address is read once at startup,
# so "edited my.cnf but did not restart mysqld" correctly FAILS. `ss` is NOT
# relied on -- it prints "*:3306" for an all-interfaces bind, never a literal
# 0.0.0.0.
#
# Two-component protocol: every check runs and is recorded with its kind, so
# "unbound 0.0.0.0 by stopping mysqld" reports security_pass=true /
# regression_pass=false instead of collapsing into a bare exit 1.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

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
    record_poc mysql_not_bound_all_ifaces 0 "port 3306 is bound to 0.0.0.0 / :: at runtime -- MySQL reachable on all interfaces (restart after editing my.cnf)"
else
    record_poc mysql_not_bound_all_ifaces 1
fi

# Config corroboration: bind-address must not be 0.0.0.0.
BIND=$(grep -iE '^\s*bind-address\s*=' "$MY_CNF" 2>/dev/null | tail -1 | sed 's/.*=\s*//' | tr -d ' \t' || true)
if [ "$BIND" = "0.0.0.0" ] || [ -z "$BIND" ]; then
    record_poc mysql_bind_address_restricted 0 "bind-address in $MY_CNF is '${BIND:-<missing>}' (must be a restricted address)"
else
    record_poc mysql_bind_address_restricted 1 "bind-address = $BIND"
fi

###############################################################################
# PoC 2: TCP-wrappers allowlist -- deny-all default plus an explicit allow.
###############################################################################
if grep -qiE '^\s*mysqld\s*:\s*ALL' "$HOSTS_DENY" 2>/dev/null; then
    record_poc hosts_deny_mysqld 1
else
    record_poc hosts_deny_mysqld 0 "$HOSTS_DENY does not contain 'mysqld: ALL'"
fi
if grep -iE '^\s*mysqld\s*:' "$HOSTS_ALLOW" 2>/dev/null | grep -qv 'ALL'; then
    record_poc hosts_allow_mysqld_specific 1
else
    record_poc hosts_allow_mysqld_specific 0 "$HOSTS_ALLOW has no specific 'mysqld:' allow entry"
fi

###############################################################################
# Regression: mysqld up + trusted_user can query over loopback.
###############################################################################
if present; then
    record_reg mysqld_listening 1
else
    record_reg mysqld_listening 0 "nothing LISTENing on 3306 -- MySQL is down"
fi

OK=$(timeout 12 mysql -h 127.0.0.1 -u trusted_user -pTrustedP@ss1 -N -e 'SELECT 1;' 2>/dev/null | tr -d ' ' || true)
if [ "$OK" = "1" ]; then
    record_reg trusted_user_query 1
else
    record_reg trusted_user_query 0 "trusted_user could not query MySQL on 127.0.0.1 (remote-trusted path broken)"
fi

verify_finish
