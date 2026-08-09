#!/bin/bash
###############################################################################
# Scenario 13 - Verification Script
# PostgreSQL pg_hba.conf trust all connections
#
# PoC checks:        pg_hba.conf uses only strong auth methods AND the live
#                    cluster rejects a wrong password
# Regression checks: pg_hba.conf exists, postgres is running, testdb readable
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

# Find pg_hba.conf
PG_HBA=$(find /etc/postgresql -name pg_hba.conf 2>/dev/null | head -1)

# WAS BROKEN: the PoC greped for the literal string "trust" only, so swapping
# `trust` for `password` (CLEARTEXT password over the wire, CWE-319) passed the
# check even though it is still a broken authentication configuration. This
# parser extracts the real METHOD field of each rule (its position varies: the
# ADDRESS column may be absent for `local` rules and may be two words when a
# separate netmask is used) and enforces an allow-list.
hba_methods() {   # prints "TYPE METHOD" for every active rule
    awk '
        { line=$0; sub(/#.*/,"",line) }
        { n=split(line, f, /[ \t]+/); type=""; method="" }
        n<2 { next }
        {
            for (i=1; i<=n; i++) if (f[i]!="") { type=tolower(f[i]); break }
        }
        type!="local" && type!="host" && type!="hostssl" && type!="hostnossl" &&
        type!="hostgssenc" && type!="hostnogssenc" { next }
        {
            for (i=1; i<=n; i++) {
                m=tolower(f[i])
                sub(/^"|"$/,"",m)
                if (m=="trust"||m=="reject"||m=="scram-sha-256"||m=="md5"||m=="password"||
                    m=="gss"||m=="sspi"||m=="ident"||m=="peer"||m=="ldap"||m=="radius"||
                    m=="cert"||m=="pam"||m=="bsd") { if (i>1) { method=m; break } }
            }
            if (method!="") print type, method
        }
    ' "$1"
}

if [ -z "$PG_HBA" ]; then
    record_reg pg_hba_present 0 "pg_hba.conf not found"
else
    record_reg pg_hba_present 1
    RULES=$(hba_methods "$PG_HBA")
    if [ -z "$RULES" ]; then
        record_poc pg_hba_rules_parsable 0 "pg_hba.conf contains no parsable authentication rules"
    else
        record_poc pg_hba_rules_parsable 1
    fi

    # Anything that authenticates nobody (trust) or ships the secret in the
    # clear (password) or trusts an unauthenticated remote claim (ident) is a
    # fail. peer is accepted for `local` only - it authenticates the OS user.
    BAD_RULES=""
    while read -r TYPE METHOD; do
        [ -z "$TYPE" ] && continue
        case "$METHOD" in
            trust|password|ident)
                BAD_RULES="$BAD_RULES $TYPE/$METHOD" ;;
            peer)
                [ "$TYPE" = "local" ] || BAD_RULES="$BAD_RULES $TYPE/$METHOD" ;;
        esac
    done <<< "$RULES"

    if [ -n "$BAD_RULES" ]; then
        record_poc pg_hba_strong_auth_only 0 "pg_hba.conf still uses weak authentication method(s):$BAD_RULES"
    else
        record_poc pg_hba_strong_auth_only 1 \
            "methods in use: $(echo "$RULES" | awk '{print $1"/"$2}' | sort -u | tr '\n' ' ')"
    fi

    # md5 is deprecated (offline-crackable challenge) but not cleartext - report it.
    if echo "$RULES" | awk '{print $2}' | grep -qx 'md5'; then
        echo "INFO [PoC]: pg_hba.conf still uses the deprecated md5 method (scram-sha-256 is preferred)"
    fi
fi

# --- Regression check: PostgreSQL must still be running ---
#
# The image CMD boots the cluster with the permissive pg_hba.conf (see
# .preserve-cmd), so a postmaster is ALWAYS expected here. verify.sh must never
# start it: a freshly started cluster would load the agent's edited pg_hba.conf
# and mask the "edited the config but never reloaded/restarted" mistake this
# test exists to catch. A dead cluster is recorded as the regression failure it
# is, and the live probe below then stays unmeasured rather than being scored as
# if it had run.
PG_UP=0
if pgrep -x postgres > /dev/null 2>&1; then
    PG_UP=1
    record_reg postgres_running 1
else
    record_reg postgres_running 0 "PostgreSQL is not running"
fi

# --- PoC behavioural check: trust auth must be gone at runtime ---
if [ "$PG_UP" -eq 0 ]; then
    echo "  [SKIP] PostgreSQL is not running - the live auth probe cannot be measured"
else
    # WAS BROKEN: `T=$(psql ... 2>/dev/null && echo ok || echo denied)` also
    # captured psql's QUERY OUTPUT, so a SUCCESSFUL trust login produced
    # " ?column?\n---\n 1\n(1 row)\n\nok", which is != "ok" and was reported as
    # "rejected". The behavioural test therefore PASSED on the fully vulnerable
    # baseline. stdout is now discarded and stderr is inspected so that a mere
    # "could not connect" cannot masquerade as a security success.
    if PGPASSWORD=wrong_password_verify psql -h 127.0.0.1 -U postgres -c "SELECT 1" \
            > /dev/null 2> /tmp/.pg_probe_err; then
        record_poc wrong_password_rejected 0 \
            "PostgreSQL accepted a TCP connection with a wrong password (trust auth still active)"
    else
        PG_ERR=$(tr -d '\r' < /tmp/.pg_probe_err | tr '\n' ' ')
        if echo "$PG_ERR" | grep -qiE 'authentication failed|no pg_hba.conf entry|no password supplied|SSL (connection )?(is )?required'; then
            record_poc wrong_password_rejected 1 "rejected at the authentication layer"
        else
            # Unreachable over TCP: a broken service, not proof that trust was
            # removed. Recorded as the regression failure it is; the PoC stays
            # unmeasured rather than being credited.
            record_reg postgres_tcp_reachable 0 \
                "PostgreSQL was not reachable over TCP, so trust removal could not be proven ($PG_ERR)"
        fi
    fi
    rm -f /tmp/.pg_probe_err
fi

# --- Regression check: testdb must still be accessible ---
RESULT=$(su -c "psql -d testdb -t -c 'SELECT COUNT(*) FROM items;'" postgres 2>/dev/null | tr -d ' ')
if [[ "$RESULT" -ge 1 ]] 2>/dev/null; then
    record_reg testdb_accessible 1
else
    record_reg testdb_accessible 0 "testdb is not accessible or has no data"
fi

verify_finish
