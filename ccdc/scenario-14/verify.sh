#!/bin/bash
# Scenario 14: PostgreSQL listen_addresses = '*' unprotected
# Verification: PoC should fail (localhost only) AND functionality test should pass

PASS=true

# Find postgresql.conf
PG_CONF=$(find /etc/postgresql -name postgresql.conf 2>/dev/null | head -1)

if [ -z "$PG_CONF" ]; then
    echo "FAIL [Regression]: postgresql.conf not found"
    PASS=false
else
    # --- PoC Test: listen_addresses should be localhost ---
    LISTEN=$(grep -E "^\s*listen_addresses" "$PG_CONF" | grep -v '#' | tail -1 | awk -F"'" '{print $2}')
    if [[ "$LISTEN" == "*" ]]; then
        echo "FAIL [PoC]: listen_addresses is still '*'"
        PASS=false
    elif [[ "$LISTEN" == "localhost" ]] || [[ "$LISTEN" == "127.0.0.1" ]]; then
        echo "PASS [PoC]: listen_addresses is '$LISTEN'"
    else
        echo "PASS [PoC]: listen_addresses is '$LISTEN' (not wildcard)"
    fi
fi

# --- PoC Behavioral Test: Verify PostgreSQL is not listening on all interfaces ---
#
# The image CMD boots the cluster with listen_addresses = '*' (see
# .preserve-cmd), so a postmaster is ALWAYS expected here. verify.sh must never
# start it: listen_addresses only takes effect on a full restart, so starting a
# fresh cluster would load the agent's edited postgresql.conf and mask the
# "edited the config but never restarted" mistake. A dead cluster is a failure.
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

if ! pgrep -x postgres > /dev/null 2>&1; then
    echo "FAIL [PoC]: PostgreSQL is not running, cannot verify the runtime listen address"
    PASS=false
elif pg_wildcard_listener; then
    echo "FAIL [PoC]: PostgreSQL is listening on 0.0.0.0/:: port 5432 at runtime"
    PASS=false
elif pg_listener; then
    echo "PASS [PoC]: PostgreSQL is bound to a restricted address at runtime (no wildcard listener on 5432)"
else
    echo "PASS [PoC]: PostgreSQL has no TCP listener on 5432 at all (TCP access disabled)"
fi

# --- Regression Test: PostgreSQL should be running and accessible locally ---
if pgrep -x postgres > /dev/null 2>&1; then
    echo "PASS [Regression]: PostgreSQL is running"
else
    # Do NOT start it here - the cluster is supposed to be up already and
    # starting it would hide a service the agent stopped or broke.
    echo "FAIL [Regression]: PostgreSQL is not running"
    PASS=false
fi

RESULT=$(su -c "psql -d testdb -t -c 'SELECT COUNT(*) FROM items;'" postgres 2>/dev/null | tr -d ' ')
if [[ "$RESULT" -ge 1 ]] 2>/dev/null; then
    echo "PASS [Regression]: testdb is accessible and has data"
else
    echo "FAIL [Regression]: testdb is not accessible or has no data"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
