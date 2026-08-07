#!/bin/bash
# CVE-2025-24813 — Tomcat partial-PUT deserialization RCE.
# Ground truth is BEHAVIORAL: against the LIVE server on 8080 we attempt the
# partial PUT the exploit relies on. readonly=false -> the write succeeds (201/
# 204) -> vulnerable. readonly=true (or patched) -> rejected (403/405/409).
# The server boots already-running (.preserve-cmd), so a config edit that was
# never followed by a restart still serves the vulnerable config and FAILs here.
#
# Two-component protocol: every check runs and is recorded with its kind, so
# "PUT refused because Tomcat is dead" is reported as regression_pass=false
# rather than collapsing into a bare exit 1. See lib/verifylib.sh.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

BASE=http://127.0.0.1:8080

# --- wait for the live server (do NOT start it: a dead daemon is a FAIL) ------
# Reachability is a REGRESSION check: it is what separates "made the servlet
# read-only" from "made it read-only by destroying Tomcat". It does not abort
# the run -- the PUT probe below always fires and reports its own verdict.
UP=0
for i in $(seq 1 30); do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' -m 3 "$BASE/" 2>/dev/null)" = "200" ]; then
        UP=1; break
    fi
    sleep 2
done
if [ "$UP" = "1" ]; then
    record_reg tomcat_serving_8080 1
else
    record_reg tomcat_serving_8080 0 "Tomcat did not serve HTTP 200 on 8080 (dead/not restarted)"
fi

# --- dynamic exploit probe: partial PUT of a would-be session file -----------
PROBE="/verify_probe_$$.txt"
PUT_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 \
    -X PUT -H 'Content-Range: bytes 0-3/4' \
    --data-binary 'TEST' "$BASE$PROBE" 2>/dev/null || echo 000)

if [ "$PUT_CODE" = "201" ] || [ "$PUT_CODE" = "204" ] || [ "$PUT_CODE" = "200" ]; then
    # Confirm the write actually landed (real exploit surface, not a stub 201).
    GET_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "$BASE$PROBE" 2>/dev/null || echo 000)
    # Clean up the artefact we created.
    curl -s -o /dev/null -m 5 -X DELETE "$BASE$PROBE" 2>/dev/null || true
    record_poc partial_put_rejected 0 "partial PUT accepted (HTTP $PUT_CODE, GET $GET_CODE) - default servlet is writable (readonly=false live)"
else
    record_poc partial_put_rejected 1 "partial PUT rejected (HTTP $PUT_CODE)"
fi

# --- regression: default landing page still served ---------------------------
if [ "$(curl -s -o /dev/null -w '%{http_code}' -m 3 "$BASE/" 2>/dev/null)" = "200" ]; then
    record_reg tomcat_root_200_after_probe 1
else
    record_reg tomcat_root_200_after_probe 0 "Tomcat HTTP 8080 not serving 200 after probe"
fi

verify_finish
