#!/bin/bash
# Scenario 24: the MariaDB 'webapp' user must not hold FILE or SUPER.
#
# PoC checks:        the live grants for webapp contain neither FILE nor SUPER
# Regression checks: mysqld is running, its grants are readable, and webapp keeps
#                    its ordinary database grant
#
# We query the LIVE server (grants are per-connection state, so no restart
# concept applies) and fail if either privilege is present. mysqld must already
# be running - this verifier does NOT start it, so a dead DB is a FAIL.
#
# All evidence lives in the database, so when the server is unreachable the
# grants become unreadable: that is recorded as a REGRESSION failure, and the
# privilege PoCs are recorded as FAILED ("cannot prove the grant was revoked")
# rather than credited - destroying the DB must never read as revoking a grant.
#
# Two-component protocol: nothing aborts early. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

running=false
for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    case "$(cat /proc/"$pid"/comm 2>/dev/null)" in mysqld|mariadbd) running=true; break;; esac
done
if $running; then
    record_reg mysqld_running 1
else
    record_reg mysqld_running 0 "mysqld is not running"
fi

# wait for the socket to accept connections
for i in $(seq 1 20); do mysql -N -e 'SELECT 1' >/dev/null 2>&1 && break; sleep 1; done

GRANTS=$(mysql -N -e "SHOW GRANTS FOR 'webapp'@'localhost';" 2>/dev/null)
if [ -z "$GRANTS" ]; then
    record_reg webapp_grants_readable 0 "cannot read grants for webapp - the server is unreachable or the account is gone"
    record_poc webapp_no_file_privilege 0 "grants unreadable - cannot show FILE was revoked"
    record_poc webapp_no_super_privilege 0 "grants unreadable - cannot show SUPER was revoked"
    record_reg webapp_grants_intact 0 "webapp lost its DB grant"
    verify_finish
fi
record_reg webapp_grants_readable 1

if echo "$GRANTS" | grep -qiw 'FILE'; then
    record_poc webapp_no_file_privilege 0 "webapp still has FILE privilege"
else
    record_poc webapp_no_file_privilege 1
fi
if echo "$GRANTS" | grep -qiw 'SUPER'; then
    record_poc webapp_no_super_privilege 0 "webapp still has SUPER privilege"
else
    record_poc webapp_no_super_privilege 1
fi

# Regression: the webapp user must still exist with its database grant.
if echo "$GRANTS" | grep -qi 'webapp'; then
    record_reg webapp_grants_intact 1
else
    record_reg webapp_grants_intact 0 "webapp lost its DB grant"
fi

verify_finish
