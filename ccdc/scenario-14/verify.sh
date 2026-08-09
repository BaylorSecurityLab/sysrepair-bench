#!/bin/bash
###############################################################################
# Scenario 14 - Verification Script
# PostgreSQL listen_addresses = '*' unprotected
#
# PoC checks:        listen_addresses is not the wildcard, in the config AND at
#                    runtime
# Regression checks: postgresql.conf exists, postgres is running, testdb readable
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
# Exit 42 = precondition does not hold on this host
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "closed the vulnerability but killed postgres" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.
###############################################################################

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# Find postgresql.conf
PG_CONF=$(find /etc/postgresql -name postgresql.conf 2>/dev/null | head -1)

if [ -z "$PG_CONF" ]; then
    record_reg postgresql_conf_present 0 "postgresql.conf not found"
else
    record_reg postgresql_conf_present 1
    # --- PoC check: listen_addresses should be localhost ---
    LISTEN=$(grep -E "^\s*listen_addresses" "$PG_CONF" | grep -v '#' | tail -1 | awk -F"'" '{print $2}')
    if [[ "$LISTEN" == "*" ]]; then
        record_poc listen_addresses_not_wildcard 0 "listen_addresses is still '*'"
    elif [[ "$LISTEN" == "localhost" ]] || [[ "$LISTEN" == "127.0.0.1" ]]; then
        record_poc listen_addresses_not_wildcard 1 "listen_addresses is '$LISTEN'"
    else
        record_poc listen_addresses_not_wildcard 1 "listen_addresses is '$LISTEN' (not wildcard)"
    fi
fi

# --- PoC behavioural check: PostgreSQL must not be listening on all interfaces ---
#
# The image CMD boots the cluster with listen_addresses = '*' (see
# .preserve-cmd), so a postmaster is ALWAYS expected here. verify.sh must never
# start it: listen_addresses only takes effect on a full restart, so starting a
# fresh cluster would load the agent's edited postgresql.conf and mask the
# "edited the config but never restarted" mistake. A dead cluster is recorded as
# the regression failure it is, and the runtime probe below then stays
# unmeasured rather than being scored as if it had run.
#
# WAS BROKEN: this check ran `ss -tlnp`, but iproute2 is NOT installed in this
# image. `ss` failed silently, PG_LISTEN came back empty and the check printed
# INFO and passed no matter what PostgreSQL was actually bound to. Parse
# /proc/net/tcp{,6} instead: state 0A = LISTEN, $2 = HEXIP:HEXPORT,
# 5432 = 0x1538, and an all-zero HEXIP is the 0.0.0.0 / :: wildcard.
pg_listener() {   # 0 = something LISTENs on 5432
    awk 'NR>1 && $4=="0A" {split($2,a,":"); if (a[2]=="1538") f=1} END{exit !f}' \
        /proc/net/tcp /proc/net/tcp6 2>/dev/null
}
pg_wildcard_listener() {   # 0 = LISTENing on 0.0.0.0 / :: (all interfaces)
    awk 'NR>1 && $4=="0A" {split($2,a,":"); if (a[2]=="1538" && a[1] ~ /^0+$/) f=1} END{exit !f}' \
        /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

# --- Regression check: PostgreSQL should be running ---
# Do NOT start it here - the cluster is supposed to be up already and starting
# it would hide a service the agent stopped or broke.
PG_UP=0
if pgrep -x postgres > /dev/null 2>&1; then
    PG_UP=1
    record_reg postgres_running 1
else
    record_reg postgres_running 0 "PostgreSQL is not running"
fi

if [ "$PG_UP" -eq 0 ]; then
    echo "  [SKIP] PostgreSQL is not running - the runtime listen address cannot be measured"
elif pg_wildcard_listener; then
    record_poc runtime_no_wildcard_listener 0 "PostgreSQL is listening on 0.0.0.0/:: port 5432 at runtime"
elif pg_listener; then
    record_poc runtime_no_wildcard_listener 1 "bound to a restricted address at runtime (no wildcard listener on 5432)"
else
    record_poc runtime_no_wildcard_listener 1 "no TCP listener on 5432 at all (TCP access disabled)"
fi

# --- Regression check: testdb must still be accessible ---
RESULT=$(su -c "psql -d testdb -t -c 'SELECT COUNT(*) FROM items;'" postgres 2>/dev/null | tr -d ' ')
if [[ "$RESULT" -ge 1 ]] 2>/dev/null; then
    record_reg testdb_accessible 1
else
    record_reg testdb_accessible 0 "testdb is not accessible or has no data"
fi

verify_finish
