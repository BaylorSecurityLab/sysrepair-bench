#!/bin/bash
# Scenario 13: PostgreSQL pg_hba.conf trust all connections
# Verification: PoC should fail (no trust auth) AND functionality test should pass

PASS=true

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
    echo "FAIL [Regression]: pg_hba.conf not found"
    PASS=false
else
    RULES=$(hba_methods "$PG_HBA")
    if [ -z "$RULES" ]; then
        echo "FAIL [PoC]: pg_hba.conf contains no parsable authentication rules"
        PASS=false
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
        echo "FAIL [PoC]: pg_hba.conf still uses weak authentication method(s):$BAD_RULES"
        PASS=false
    else
        echo "PASS [PoC]: pg_hba.conf uses only strong authentication methods ($(echo "$RULES" | awk '{print $1"/"$2}' | sort -u | tr '\n' ' '))"
    fi

    # md5 is deprecated (offline-crackable challenge) but not cleartext - report it.
    if echo "$RULES" | awk '{print $2}' | grep -qx 'md5'; then
        echo "INFO [PoC]: pg_hba.conf still uses the deprecated md5 method (scram-sha-256 is preferred)"
    fi
fi

# --- PoC Behavioral Test: Verify trust auth is gone by attempting connection with wrong password ---
#
# The image CMD boots the cluster with the permissive pg_hba.conf (see
# .preserve-cmd), so a postmaster is ALWAYS expected here. verify.sh must never
# start it: a freshly started cluster would load the agent's edited pg_hba.conf
# and mask the "edited the config but never reloaded/restarted" mistake this
# test exists to catch. A dead cluster is a failure, not something to fix.
if pgrep -x postgres > /dev/null 2>&1; then
    # WAS BROKEN: `T=$(psql ... 2>/dev/null && echo ok || echo denied)` also
    # captured psql's QUERY OUTPUT, so a SUCCESSFUL trust login produced
    # " ?column?\n---\n 1\n(1 row)\n\nok", which is != "ok" and was reported as
    # "rejected". The behavioural test therefore PASSED on the fully vulnerable
    # baseline. stdout is now discarded and stderr is inspected so that a mere
    # "could not connect" cannot masquerade as a security success.
    if PGPASSWORD=wrong_password_verify psql -h 127.0.0.1 -U postgres -c "SELECT 1" \
            > /dev/null 2> /tmp/.pg_probe_err; then
        echo "FAIL [PoC]: PostgreSQL accepted a TCP connection with a wrong password (trust auth still active)"
        PASS=false
    else
        PG_ERR=$(tr -d '\r' < /tmp/.pg_probe_err | tr '\n' ' ')
        if echo "$PG_ERR" | grep -qiE 'authentication failed|no pg_hba.conf entry|no password supplied|SSL (connection )?(is )?required'; then
            echo "PASS [PoC]: PostgreSQL rejected the wrong password at the authentication layer"
        else
            echo "FAIL [PoC]: PostgreSQL was not reachable over TCP, so trust removal could not be proven ($PG_ERR)"
            PASS=false
        fi
    fi
    rm -f /tmp/.pg_probe_err
else
    echo "FAIL [PoC]: PostgreSQL is not running, cannot verify authentication behaviour"
    PASS=false
fi

# --- Regression Test: PostgreSQL should be running ---
if pgrep -x postgres > /dev/null 2>&1; then
    echo "PASS [Regression]: PostgreSQL is running"
else
    # Do NOT start it here - the cluster is supposed to be up already and
    # starting it would hide a service the agent stopped or broke.
    echo "FAIL [Regression]: PostgreSQL is not running"
    PASS=false
fi

# Check testdb is accessible
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
