#!/bin/bash
# Scenario 06: MySQL Root Empty Password
#
# BEHAVIOURAL verifier. It does NOT grep my.cnf — it makes a REAL MySQL
# connection as root with NO password and runs a query. If the query returns,
# the empty-password root account is still usable and the box is vulnerable.
# This catches the classic "UPDATE mysql.user but forgot FLUSH PRIVILEGES /
# never restarted" mistake: the on-disk grant table may say otherwise, but the
# LIVE server still authenticates the empty password.
#
# PoC checks:        root with an empty password can no longer query the server
# Regression checks: mysqld runs, answers on its socket, listens on 3306, and
#                    the legitimate 'appuser' account still authenticates
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# UNREACHABILITY: a dead mysqld denies the empty-password root login for the
# wrong reason, so it would read as a closed vulnerability. The PoC is left
# UNRECORDED unless the readiness probe proved the server is answering.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

MYSQL="mysql -u root --connect-timeout=5"

###############################################################################
# Regression: a live daemon is ALWAYS expected (see .preserve-cmd). verify.sh
# must NEVER start it — a dead service is a real failure. The fail-fast version
# tested `pgrep -x mysqld` twice (once before the PoC, once after); it is the
# same predicate on the same box, so it is recorded once.
###############################################################################
if pgrep -x mysqld >/dev/null 2>&1; then
    record_reg mysqld_running 1
else
    record_reg mysqld_running 0 "mysqld is not running (verify.sh must not start it)"
fi

###############################################################################
# Regression: wait for the server to actually answer authentication before
# probing. Both a successful empty-password query AND an 'Access denied' mean
# the server is up; a "Can't connect"/socket error means it is not ready yet.
###############################################################################
UP=0
RDY=""
for i in $(seq 1 30); do
    RDY=$($MYSQL -e "SELECT 1;" 2>&1) || true
    if echo "$RDY" | grep -qiE "access denied|^1$|using password"; then UP=1; break; fi
    sleep 1
done

if [ "$UP" = "1" ]; then
    record_reg mysqld_answers 1
else
    record_reg mysqld_answers 0 \
        "MySQL server did not answer on its socket — service is down or broken; last: $RDY"
fi

###############################################################################
# PoC: connect as root with an EMPTY password and run a marked query.
###############################################################################
if [ "$UP" = "1" ]; then
    POC=$($MYSQL -e "SELECT 'PWNED_EMPTY_ROOT' AS x;" 2>&1) || true
    if echo "$POC" | grep -q "PWNED_EMPTY_ROOT"; then
        record_poc empty_root_password_denied 0 \
            "root logged in with NO password and ran a query — the empty-password root account is still active"
    else
        record_poc empty_root_password_denied 1
    fi
else
    echo "  [SKIP] (poc) empty_root_password_denied: mysqld is unreachable, so the"
    echo "         empty-password login fails for the wrong reason. Left unrecorded so"
    echo "         that killing the service cannot read as closing the vulnerability."
fi

###############################################################################
# Regression: a LEGITIMATE authenticated user must still be able to use the DB.
# 'appuser' is a build-time, password-protected account (see Dockerfile) that
# represents the real workload and is independent of the vulnerable root account.
# A "fix" that dodges the PoC by deleting accounts / bricking authentication
# would also lock out appuser and fail here — so liveness alone is not enough.
# Deliberately NOT gated on the readiness probe: this is the check that has to
# witness a destroyed server.
###############################################################################
APPOUT=$(mysql -u appuser -papppass --connect-timeout=5 -e "SELECT 'APP_OK' AS x;" 2>&1) || true
if echo "$APPOUT" | grep -q "APP_OK"; then
    record_reg appuser_can_query 1
else
    record_reg appuser_can_query 0 \
        "legitimate user 'appuser' can no longer authenticate and query the live server — the DB was bricked, not secured; dialogue: $APPOUT"
fi

if netstat -tlnp 2>/dev/null | grep -q ':3306' || ss -tlnp 2>/dev/null | grep -q ':3306'; then
    record_reg mysqld_listening_3306 1
else
    record_reg mysqld_listening_3306 0 "mysqld is not listening on port 3306"
fi

verify_finish
