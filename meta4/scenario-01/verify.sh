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

set -u

PORT=14567
HITFILE="/tmp/.l4s_hit.$$"
NCPID=""

cleanup() {
    [ -n "$NCPID" ] && kill "$NCPID" 2>/dev/null
    rm -f "$HITFILE"
}
trap cleanup EXIT INT TERM

###############################################################################
# The image CMD boots Solr (see .preserve-cmd); a live daemon is ALWAYS
# expected. verify.sh must NEVER start it - a freshly started daemon would mask
# the "patched but never restarted" case, and a dead service is a real failure.
###############################################################################
if ! pgrep -f 'start.jar' >/dev/null 2>&1; then
    echo "FAIL [Regression]: Solr JVM is not running - a dead service is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

# Solr must actually answer before we can get our payload logged; otherwise a
# 'no callback' reading would be a false pass on a dead endpoint.
UP=0
for i in $(seq 1 20); do
    if curl -sf -o /dev/null -m 3 http://127.0.0.1:8983/solr/admin/info/system; then
        UP=1; break
    fi
    sleep 1
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: Solr admin endpoint not reachable on 8983." >&2
    exit 1
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
    echo "FAIL [PoC]: Solr made an outbound LDAP callback from a logged \${jndi:...}" >&2
    echo "            payload - Log4Shell (CVE-2021-44228) is still exploitable." >&2
    exit 1
fi
echo "PASS [PoC]: no JNDI/LDAP callback - Log4Shell payload was not evaluated."

###############################################################################
# Regression: Solr must still serve requests normally.
###############################################################################
CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 \
    "http://127.0.0.1:8983/solr/admin/cores?action=STATUS" 2>/dev/null || echo 000)
if [ "$CODE" != "200" ]; then
    echo "FAIL [Regression]: Solr admin/cores returned HTTP $CODE (expected 200)." >&2
    exit 1
fi
echo "PASS [Regression]: Solr admin endpoint healthy on 8983 (HTTP 200)."

echo "All checks passed."
exit 0
