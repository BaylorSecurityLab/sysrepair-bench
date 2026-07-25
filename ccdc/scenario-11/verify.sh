#!/bin/bash
# Scenario 11: MySQL remote root login + no bind-address
# Verification: PoC should fail (no remote access) AND functionality test should pass

PASS=true

# WAS BROKEN: the runtime bind-address check used `ss -tlnp`, but iproute2 is
# NOT installed in this image. `ss` failed silently, LISTEN_ADDR came back empty
# and the check was skipped entirely - the config grep was the only thing
# enforcing anything. These helpers parse /proc/net/tcp{,6} instead
# (state 0A = LISTEN, $2 = HEXIP:HEXPORT; 3306 = 0x0CEA).
# `pgrep` alone is also unsafe here: PID 1 is `sleep infinity` and never reaps,
# so killed daemons linger as zombies that pgrep still matches.
proc_alive() {
    local p st
    for p in $(pgrep -x "$1" 2>/dev/null); do
        st=$(awk '{print $3}' "/proc/$p/stat" 2>/dev/null)
        [ -n "$st" ] && [ "$st" != "Z" ] && return 0
    done
    return 1
}

listener_on_3306() {   # 0 = something is LISTENing on 3306
    awk 'NR>1 && $4=="0A" {split($2,a,":"); if (a[2]=="0CEA") f=1} END{exit !f}' \
        /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

wildcard_listener_on_3306() {  # 0 = LISTENing on 0.0.0.0 / :: (all interfaces)
    awk 'NR>1 && $4=="0A" {split($2,a,":"); if (a[2]=="0CEA" && a[1] ~ /^0+$/) f=1} END{exit !f}' \
        /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

# WAS BROKEN (design): this used to be an `ensure_mysqld` helper that STARTED
# the daemon when it was not running. The image CMD now boots mysqld with the
# vulnerable config (see .preserve-cmd), so a daemon is always expected here.
# Starting one would load the agent's edited my.cnf and silently repair the
# "edited the config but never restarted mysqld" mistake - and would equally
# hide a daemon the agent stopped or broke. A dead mysqld is a FAILURE.
mysqld_alive() {
    proc_alive mysqld
}

# --- PoC Test: bind-address should be 127.0.0.1 ---
BIND=$(grep -rE '^\s*bind-address' /etc/mysql/ 2>/dev/null | grep -v '#' | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')
if [[ "$BIND" == "0.0.0.0" ]] || [[ "$BIND" == "*" ]] || [[ -z "$BIND" ]]; then
    echo "FAIL [PoC]: bind-address is '$BIND' (should be 127.0.0.1)"
    PASS=false
else
    echo "PASS [PoC]: bind-address is '$BIND'"
fi

# --- PoC Test: skip-grant-tables should not be set ---
SKIP_GRANTS=$(grep -rE '^\s*skip-grant-tables' /etc/mysql/ 2>/dev/null | grep -v '#')
if [ -n "$SKIP_GRANTS" ]; then
    echo "FAIL [PoC]: skip-grant-tables is still enabled"
    PASS=false
else
    echo "PASS [PoC]: skip-grant-tables is not set"
fi

# --- The behavioural checks below interrogate the LIVE daemon ---
mysqld_alive
MYSQLD_UP=$?

# --- PoC Behavioral Test: skip-grant-tables should be gone at runtime ---
if [ "$MYSQLD_UP" -eq 0 ]; then
    # WAS BROKEN: `X=$(mysql ... 2>/dev/null && echo ok || echo denied)` captures
    # the QUERY OUTPUT as well, so a successful login yielded "1\n1\nok", which
    # is != "ok" and was misreported as "access denied". stdout must be silenced.
    SKIP_GRANT_TEST=$(mysql -u root --skip-password -e "SELECT 1" >/dev/null 2>&1 && echo "ok" || echo "denied")
    if [[ "$SKIP_GRANT_TEST" == "ok" ]]; then
        # This could mean skip-grant-tables is active OR root has no password.
        # Check more specifically: try an obviously-wrong password
        WRONG_PW_TEST=$(mysql -u root -p'__wrong_pw_verify__' -e "SELECT 1" >/dev/null 2>&1 && echo "ok" || echo "denied")
        if [[ "$WRONG_PW_TEST" == "ok" ]]; then
            echo "FAIL [PoC]: MySQL accepts any credentials — skip-grant-tables likely still active"
            PASS=false
        else
            echo "PASS [PoC]: MySQL root can connect without password but rejects wrong passwords (auth is enforced)"
        fi
    else
        echo "PASS [PoC]: Unauthenticated MySQL access denied (skip-grant-tables is off)"
    fi
else
    echo "FAIL [PoC]: mysqld is not running, cannot verify authentication at runtime"
    PASS=false
fi

# --- PoC Behavioral Test: Verify bind address at runtime ---
if [ "$MYSQLD_UP" -ne 0 ]; then
    echo "FAIL [PoC]: mysqld is not running, cannot verify the runtime bind address"
    PASS=false
elif wildcard_listener_on_3306; then
    echo "FAIL [PoC]: MySQL is listening on 0.0.0.0/:: port 3306 at runtime"
    PASS=false
elif listener_on_3306; then
    echo "PASS [PoC]: MySQL is bound to a restricted address at runtime (no wildcard listener on 3306)"
else
    echo "PASS [PoC]: MySQL has no TCP listener on 3306 at all (networking disabled)"
fi

# --- Regression Test: MySQL should be running and accessible locally ---
if proc_alive mysqld; then
    echo "PASS [Regression]: mysqld process is running"
else
    echo "FAIL [Regression]: mysqld is not running"
    PASS=false
fi

# Check that testdb is accessible
RESULT=$(mysql -u root -e "SELECT COUNT(*) FROM testdb.items;" 2>/dev/null | tail -1)
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
