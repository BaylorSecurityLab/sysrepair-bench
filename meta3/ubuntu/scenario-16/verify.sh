#!/bin/bash
# Verification script for Scenario 16: MySQL 5.5 bind-address + hosts.allow allowlist
# Category: Compensating Control
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
# Run inside the container: docker exec meta3u-s16 /bin/bash /verify.sh

MY_CNF="/etc/mysql/my.cnf"
HOSTS_ALLOW="/etc/hosts.allow"
HOSTS_DENY="/etc/hosts.deny"

###############################################################################
# PoC Check 1: bind-address must NOT be 0.0.0.0
###############################################################################

# Normalise: strip whitespace around the = sign
BIND_ADDR=$(grep -i '^\s*bind-address\s*=' "$MY_CNF" 2>/dev/null | \
    tail -1 | sed 's/.*=\s*//' | tr -d ' \t')

if [ -z "$BIND_ADDR" ]; then
    echo "FAIL [PoC-Config]: No 'bind-address' directive found in $MY_CNF." >&2
    exit 1
fi

if [ "$BIND_ADDR" = "0.0.0.0" ]; then
    echo "FAIL [PoC-Config]: bind-address is still '0.0.0.0' -- MySQL is reachable on all interfaces." >&2
    exit 1
fi

echo "PASS [PoC-Config]: bind-address = $BIND_ADDR (not 0.0.0.0)."

# Runtime check: port 3306 must not appear bound to 0.0.0.0 in ss output
if ss -tlnp 2>/dev/null | grep ':3306' | grep -q '0\.0\.0\.0'; then
    echo "FAIL [PoC-Runtime]: Port 3306 is still bound to 0.0.0.0 at runtime." >&2
    echo "  Restart MySQL after editing my.cnf." >&2
    exit 1
fi

echo "PASS [PoC-Runtime]: Port 3306 is not bound to 0.0.0.0."

###############################################################################
# PoC Check 2: /etc/hosts.deny must contain a mysqld deny-all rule
###############################################################################

if ! grep -qi 'mysqld\s*:\s*ALL' "$HOSTS_DENY" 2>/dev/null; then
    echo "FAIL [PoC-HostsDeny]: $HOSTS_DENY does not contain 'mysqld: ALL'." >&2
    echo "  Add: mysqld: ALL" >&2
    exit 1
fi

echo "PASS [PoC-HostsDeny]: $HOSTS_DENY contains 'mysqld: ALL'."

###############################################################################
# PoC Check 3: /etc/hosts.allow must permit a specific trusted subnet/host
###############################################################################

if ! grep -qi 'mysqld\s*:' "$HOSTS_ALLOW" 2>/dev/null; then
    echo "FAIL [PoC-HostsAllow]: $HOSTS_ALLOW does not contain any 'mysqld:' allowlist entry." >&2
    echo "  Add: mysqld: <trusted-subnet-or-ip>" >&2
    exit 1
fi

ALLOW_ENTRY=$(grep -i 'mysqld\s*:' "$HOSTS_ALLOW" | grep -v '^\s*#' | head -1)
echo "PASS [PoC-HostsAllow]: $HOSTS_ALLOW has allowlist entry: $ALLOW_ENTRY"

###############################################################################
# Regression Check: MySQL is running and local trusted_user can connect
###############################################################################

if ! pgrep -x mysqld > /dev/null 2>&1 && ! pgrep -x mysqld_safe > /dev/null 2>&1; then
    echo "FAIL [Regression]: MySQL daemon is not running." >&2
    exit 1
fi

echo "PASS [Regression]: MySQL daemon is running."

QUERY_RESULT=$(mysql -h 127.0.0.1 -u trusted_user -pTrustedP@ss1 \
    -e "SELECT 1 AS ok;" 2>/dev/null | grep -c '1')

if [ "$QUERY_RESULT" -ge 1 ] 2>/dev/null; then
    echo "PASS [Regression]: trusted_user can connect to MySQL on 127.0.0.1 and execute queries."
else
    echo "FAIL [Regression]: trusted_user could not connect to MySQL on 127.0.0.1." >&2
    echo "  Ensure MySQL is running and trusted_user@localhost has SELECT privilege." >&2
    exit 1
fi

echo "All checks passed."
exit 0
