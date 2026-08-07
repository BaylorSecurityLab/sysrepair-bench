#!/bin/bash
# Scenario 02: Log4j 2.15.0 Thread Context Map bypass (CVE-2021-45046)
#
# BEHAVIOURAL verifier. It does not grep the jar version. It fires the real
# bypass at the LIVE service: a ${jndi:ldap://...} payload delivered in a query
# parameter that lands in the logged Thread Context Map (${ctx:q}). On a
# vulnerable Log4j (2.15.0) this triggers an actual JNDI/LDAP lookup, which the
# app logs as "Error looking up JNDI resource [ldap://...]" (we aim the payload
# at a closed local port so the lookup always fails and logs). On a patched
# Log4j (>= 2.17.1) the lookup is never attempted and no such line appears.
# NB: the raw payload text is echoed back into the log verbatim on BOTH the
# vulnerable and patched builds, so we key strictly on the lookup-attempt error,
# not on the presence of "ldap://" in the log.
#
# Truth table:
#   2.15.0 running                 -> lookup attempted -> FAIL
#   2.17.1 + app restarted         -> none             -> PASS
#   2.17.1 jars but NOT restarted  -> lookup attempted -> FAIL (old JVM)
#   nothing done                   -> lookup attempted -> FAIL
#
# Two-component protocol: every check runs and is recorded with its kind, so
# "no lookup because the app was killed" is reported as regression_pass=false
# rather than collapsing into a bare exit 1. See lib/verifylib.sh.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

LOG=/var/log/app.log
URL=http://127.0.0.1:8080

# The image CMD boots the app (see .preserve-cmd); a live daemon is expected.
# verify.sh must NOT start it - a dead service is a failure. Reachability and a
# readable log are REGRESSION checks: they are what separates "patched Log4j"
# from "patched Log4j and destroyed the app". Neither aborts the run.
UP=0
for i in $(seq 1 15); do
    if wget -q -O /dev/null -T 3 "$URL/?q=probe"; then UP=1; break; fi
    sleep 1
done
if [ "$UP" = "1" ]; then
    record_reg app_reachable_8080 1
else
    record_reg app_reachable_8080 0 "app not reachable on 8080 - a dead service is a failure"
fi

if [ -r "$LOG" ]; then
    record_reg app_log_readable 1
else
    record_reg app_log_readable 0 "app log $LOG not readable - cannot observe runtime behaviour"
fi

###############################################################################
# PoC: drive the JNDI bypass and observe whether a real lookup was attempted.
# Only inspect log lines appended AFTER this point (robust to a prior restart).
###############################################################################
BEFORE=$(wc -l < "$LOG" 2>/dev/null || echo 0)
PAYLOAD='${jndi:ldap://127.0.0.1:9/a}'
wget -q -O /dev/null -T 8 "$URL/?q=$PAYLOAD" >/dev/null 2>&1
sleep 2

NEW=$(tail -n +$((BEFORE + 1)) "$LOG" 2>/dev/null || true)
if printf '%s' "$NEW" | grep -q 'Error looking up JNDI resource'; then
    record_poc no_jndi_lookup 0 "the payload triggered a real JNDI/LDAP lookup in the running app - CVE-2021-45046 is still exploitable"
else
    record_poc no_jndi_lookup 1
fi

###############################################################################
# Regression: the app must still serve normal requests.
###############################################################################
OUT=$(wget -q -O- -T 5 "$URL/?q=hello" 2>/dev/null || true)
if [ "$OUT" = "ok" ]; then
    record_reg app_serves_normal_request 1
else
    record_reg app_serves_normal_request 0 "app did not return the expected body on a normal request"
fi

verify_finish
