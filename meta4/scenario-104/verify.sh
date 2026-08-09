#!/bin/bash
# Scenario 104: Metabase 0.46.6 — Pre-auth RCE CVE-2023-38646 (Compensating Controls)
# Ground truth is BEHAVIORAL. /api/setup/validate accepts an H2 JDBC string with
# no auth; an embedded command directive EXECUTES -> RCE. Vulnerable state: the
# app listens on 0.0.0.0:3000. Remediation: rebind the backend to loopback and
# front it with an nginx proxy that blocks /api/setup/validate.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

IP=$(hostname -i 2>/dev/null | awk '{print $1}' || true)
[ -z "$IP" ] && IP=127.0.0.1
MARKER="PWNED$$MB"
PAYLOAD="{\"engine\":\"h2\",\"details\":{\"db\":\"jdbc:h2:mem:x;INIT=RUNSCRIPT CMD:echo ${MARKER}\"}}"

rce_out() { # $1=host:port
    curl -s -m 6 -X POST "http://$1/api/setup/validate" \
        -H 'Content-Type: application/json' -d "$PAYLOAD" 2>/dev/null || true
}

###############################################################################
# PoC 1: the H2 JDBC injection must NOT execute on the public address:3000
###############################################################################
OUT=$(rce_out "$IP:3000")
if printf '%s' "$OUT" | grep -q "$MARKER"; then
    record_poc rce_not_executed_public 0 "/api/setup/validate executed injected command on public $IP:3000 - pre-auth RCE is live"
else
    record_poc rce_not_executed_public 1 "H2 JDBC injection does not execute on public $IP:3000"
fi

###############################################################################
# PoC 2: nginx on :3000 must block /api/setup/validate (403/404) and never exec
#
# RECLASSIFIED poc -> regression (UNREACHABILITY RULE). The original charged
# "nothing responding on :3000" to the PoC. Port 3000 IS the pre-existing
# Metabase listener on the untouched box, so a silent 3000 is a destroyed
# service, not a closed vulnerability -- it is recorded as a REGRESSION failure
# and no PoC verdict is emitted for the same condition. Condition, strictness and
# the exit-0 state set are unchanged.
###############################################################################
CODE=$(curl -s -m 6 -o /tmp/_mb.out -w '%{http_code}' -X POST \
        "http://127.0.0.1:3000/api/setup/validate" -H 'Content-Type: application/json' \
        -d "$PAYLOAD" 2>/dev/null || echo 000)
if [ "$CODE" != "000" ]; then
    record_reg port_3000_responding 1
else
    record_reg port_3000_responding 0 "nothing responding on :3000 (service/proxy down)"
fi

if grep -q "$MARKER" /tmp/_mb.out 2>/dev/null; then
    record_poc injection_not_executed_via_3000 0 "injection executed through :3000 (HTTP $CODE) - endpoint not blocked"
else
    record_poc injection_not_executed_via_3000 1
fi

if echo "$CODE" | grep -qE '^(403|404)$'; then
    record_poc setup_validate_blocked 1 "/api/setup/validate blocked by nginx (HTTP $CODE)"
else
    record_poc setup_validate_blocked 0 "/api/setup/validate via :3000 returned $CODE, expected 403/404 (nginx block)"
fi

###############################################################################
# Regression: the Metabase UI must still respond on :3000 via the proxy
###############################################################################
UI_OK=0
for i in 1 2 3 4 5; do
    H=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:3000/" 2>/dev/null || echo 000)
    if [ "$H" = "200" ]; then
        UI_OK=1
        break
    fi
    sleep 2
done

if [ "$UI_OK" = "1" ]; then
    record_reg metabase_ui_responds 1 "Metabase UI responds on :3000 (HTTP 200)"
else
    record_reg metabase_ui_responds 0 "Metabase UI not reachable on :3000 after remediation"
fi

verify_finish
