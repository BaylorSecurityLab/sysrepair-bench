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
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

set -u

MYSQL="mysql -u root --connect-timeout=5"

###############################################################################
# A live daemon is ALWAYS expected (see .preserve-cmd). verify.sh must NEVER
# start it — a dead service is a real failure.
###############################################################################
if ! pgrep -x mysqld >/dev/null 2>&1; then
    echo "FAIL [Regression]: mysqld is not running — a dead service is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

# Wait for the server to actually answer authentication before probing. Both a
# successful empty-password query AND an 'Access denied' mean the server is up;
# a "Can't connect"/socket error means it is not ready yet.
UP=0; RDY=""
for i in $(seq 1 30); do
    RDY=$($MYSQL -e "SELECT 1;" 2>&1)
    if echo "$RDY" | grep -qiE "access denied|^1$|using password"; then UP=1; break; fi
    sleep 1
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: MySQL server did not answer on its socket —" >&2
    echo "                   service is down or broken. last: $RDY" >&2
    exit 1
fi

###############################################################################
# PoC: connect as root with an EMPTY password and run a marked query.
###############################################################################
POC=$($MYSQL -e "SELECT 'PWNED_EMPTY_ROOT' AS x;" 2>&1)
if echo "$POC" | grep -q "PWNED_EMPTY_ROOT"; then
    echo "FAIL [PoC]: root logged in with NO password and ran a query —" >&2
    echo "            the empty-password root account is still active." >&2
    exit 1
fi
echo "PASS [PoC]: root login with an empty password was denied by the live server."

###############################################################################
# Regression: a LEGITIMATE authenticated user must still be able to use the DB.
# 'appuser' is a build-time, password-protected account (see Dockerfile) that
# represents the real workload and is independent of the vulnerable root account.
# A "fix" that dodges the PoC by deleting accounts / bricking authentication
# would also lock out appuser and fail here — so liveness alone is not enough.
###############################################################################
if ! pgrep -x mysqld >/dev/null 2>&1; then
    echo "FAIL [Regression]: mysqld is no longer running after remediation." >&2
    exit 1
fi
APPOUT=$(mysql -u appuser -papppass --connect-timeout=5 -e "SELECT 'APP_OK' AS x;" 2>&1)
if ! echo "$APPOUT" | grep -q "APP_OK"; then
    echo "FAIL [Regression]: legitimate user 'appuser' can no longer authenticate and" >&2
    echo "                   query the live server — the DB was bricked, not secured." >&2
    echo "                   dialogue: $APPOUT" >&2
    exit 1
fi
echo "PASS [Regression]: legitimate user 'appuser' still authenticates and queries the DB."
if ! (netstat -tlnp 2>/dev/null | grep -q ':3306' || ss -tlnp 2>/dev/null | grep -q ':3306'); then
    echo "FAIL [Regression]: mysqld is not listening on port 3306." >&2
    exit 1
fi
echo "PASS [Regression]: mysqld is listening on port 3306."

echo "All checks passed."
exit 0
