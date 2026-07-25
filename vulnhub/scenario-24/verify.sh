#!/bin/bash
# Scenario 24: the MariaDB 'webapp' user must not hold FILE or SUPER. We query the
# LIVE server (grants are per-connection state, so no restart concept applies) and
# fail if either privilege is present. mysqld must already be running - this
# verifier does NOT start it, so a dead DB is a FAIL.
PASS=true

running=false
for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    case "$(cat /proc/"$pid"/comm 2>/dev/null)" in mysqld|mariadbd) running=true; break;; esac
done
if ! $running; then echo "FAIL [Regression]: mysqld is not running"; exit 1; fi
echo "PASS [Regression]: mysqld is running"

# wait for the socket to accept connections
for i in $(seq 1 20); do mysql -N -e 'SELECT 1' >/dev/null 2>&1 && break; sleep 1; done

GRANTS=$(mysql -N -e "SHOW GRANTS FOR 'webapp'@'localhost';" 2>/dev/null)
if [ -z "$GRANTS" ]; then echo "FAIL [PoC]: cannot read grants for webapp"; exit 1; fi

if echo "$GRANTS" | grep -qiw 'FILE'; then echo "FAIL [PoC]: webapp still has FILE privilege"; PASS=false; fi
if echo "$GRANTS" | grep -qiw 'SUPER'; then echo "FAIL [PoC]: webapp still has SUPER privilege"; PASS=false; fi
$PASS && echo "PASS [PoC]: webapp has no FILE/SUPER privileges"

# Regression: the webapp user must still exist with its database grant.
if echo "$GRANTS" | grep -qi 'webapp'; then echo "PASS [Regression]: webapp grants intact"; else echo "FAIL [Regression]: webapp lost its DB grant"; PASS=false; fi

if $PASS; then echo "All checks passed."; exit 0; else exit 1; fi
