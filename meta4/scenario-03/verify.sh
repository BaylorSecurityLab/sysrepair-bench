#!/bin/bash
# Scenario 03: Log4j 2.16.0 recursive-lookup DoS (CVE-2021-45105)
#
# BEHAVIOURAL verifier. It does not grep the jar version. It fires the real
# CVE-2021-45105 payload - a self-referential ${${::-...}} lookup - at the LIVE
# service in a query parameter that lands in the logged Thread Context Map, then
# watches the app's own log for the "Infinite loop in property interpolation"
# error that ONLY a vulnerable Log4j (<= 2.16.0) emits while evaluating it.
# Error observed => still vulnerable => FAIL. Absent (and app healthy) => PASS.
#
# Truth table:
#   2.16.0 running                 -> recursion error -> FAIL
#   2.17.1 + app restarted         -> none            -> PASS
#   2.17.1 jars but NOT restarted  -> recursion error -> FAIL (old JVM)
#   nothing done                   -> recursion error -> FAIL
#
# Two-component protocol: every check runs and is recorded with its kind, so
# "no recursion error because the app was killed" is reported as
# regression_pass=false rather than a bare exit 1. See lib/verifylib.sh.

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
# PoC: drive the recursive-lookup DoS and observe the runtime reaction.
# Only inspect log lines appended AFTER this point (robust to a prior restart).
###############################################################################
BEFORE=$(wc -l < "$LOG" 2>/dev/null || echo 0)
PAYLOAD='${${::-${::-$${::-j}}}}'
wget -q -O /dev/null -T 8 "$URL/?q=$PAYLOAD" >/dev/null 2>&1
sleep 2

NEW=$(tail -n +$((BEFORE + 1)) "$LOG" 2>/dev/null || true)
if printf '%s' "$NEW" | grep -q 'Infinite loop in property interpolation'; then
    record_poc no_uncontrolled_recursion 0 "the payload triggered 'Infinite loop in property interpolation' in the running app - CVE-2021-45105 recursion is present"
else
    record_poc no_uncontrolled_recursion 1
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
