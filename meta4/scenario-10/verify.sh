#!/bin/bash
# CVE-2024-50379 — Tomcat case-insensitive JSP upload race. The exploitable
# precondition is the writable default servlet (readonly=false). Ground truth
# is BEHAVIORAL against the LIVE server on 8080: a PUT that lands a file proves
# the servlet is writable. Boots already-running (.preserve-cmd), so a config
# edit without a restart still serves the vulnerable config and FAILs here.
#
# Two-component protocol: every check runs and is recorded with its kind, so
# "PUT refused because Tomcat is dead" is reported as regression_pass=false
# rather than collapsing into a bare exit 1. See lib/verifylib.sh.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

BASE=http://127.0.0.1:8080

# Reachability is a REGRESSION check: it is what separates "made the servlet
# read-only" from "made it read-only by destroying Tomcat". It does not abort
# the run -- the PUT probe below always fires and reports its own verdict.
UP=0
for i in $(seq 1 30); do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' -m 3 "$BASE/" 2>/dev/null)" = "200" ]; then UP=1; break; fi
    sleep 2
done
if [ "$UP" = "1" ]; then
    record_reg tomcat_serving_8080 1
else
    record_reg tomcat_serving_8080 0 "Tomcat did not serve HTTP 200 on 8080 (dead/not restarted)"
fi

# --- dynamic probe: writable default servlet -------------------------------
PROBE="/verify_probe_$$.txt"
PUT_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -X PUT --data-binary 'TEST' "$BASE$PROBE" 2>/dev/null || echo 000)
if [ "$PUT_CODE" = "201" ] || [ "$PUT_CODE" = "204" ] || [ "$PUT_CODE" = "200" ]; then
    GET_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "$BASE$PROBE" 2>/dev/null || echo 000)
    curl -s -o /dev/null -m 5 -X DELETE "$BASE$PROBE" 2>/dev/null || true
    record_poc default_servlet_readonly 0 "PUT accepted (HTTP $PUT_CODE, GET $GET_CODE) - default servlet writable (readonly=false live)"
else
    record_poc default_servlet_readonly 1 "PUT rejected (HTTP $PUT_CODE)"
fi

if [ "$(curl -s -o /dev/null -w '%{http_code}' -m 3 "$BASE/" 2>/dev/null)" = "200" ]; then
    record_reg tomcat_root_200_after_probe 1
else
    record_reg tomcat_root_200_after_probe 0 "Tomcat HTTP 8080 not serving 200 after probe"
fi

verify_finish
