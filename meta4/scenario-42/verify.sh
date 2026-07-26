#!/bin/bash
# Scenario 42: CouchDB 3.2.1 — Default Erlang Cookie RCE (CVE-2022-24706)
#
# PoC (DYNAMIC exploit against the LIVE Erlang node): use the bundled erl_call
# to connect to the CouchDB distribution node with the default cookie "monster"
# and execute `os:cmd("id")`.  If that returns the couchdb uid, the running node
# still accepts the default cookie => unauthenticated RCE => VULNERABLE.
#
#   config fixed + restarted  -> monster rejected            -> PASS
#   config fixed + NOT restarted -> live node still monster   -> FAIL
#   config not fixed          -> monster accepted             -> FAIL
#
# Regression: CouchDB HTTP API must still be reachable on 5984.
set -u

VM_ARGS="/opt/couchdb/etc/vm.args"
ERL_CALL="$(ls /opt/couchdb/erts-*/bin/erl_call 2>/dev/null | head -1)"

###############################################################################
# Wait for the node to be up so the exploit targets a live node (and a slow
# boot is not mistaken for "fixed").
###############################################################################
UP=""
for i in $(seq 1 60); do
    UP=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5984/_up 2>/dev/null)
    [ "$UP" = "200" ] && break
    sleep 2
done
if [ "$UP" != "200" ]; then
    echo "FAIL [Regression]: CouchDB not reachable on 5984 (service down)." >&2
    exit 1
fi

# Discover the node name from vm.args (default couchdb@127.0.0.1).
NODE=$(grep -E '^\s*-name\s+' "$VM_ARGS" 2>/dev/null | awk '{print $2}' | head -1)
[ -z "$NODE" ] && NODE="couchdb@127.0.0.1"

###############################################################################
# PoC (DYNAMIC): attempt RCE with the default cookie.
###############################################################################
if [ -n "$ERL_CALL" ] && [ -x "$ERL_CALL" ]; then
    # Give erlang distribution a moment to be listening.
    # Connect to the TARGET CouchDB node ($NODE) with -name, presenting our own
    # hidden node name via -h. (-name specifies the node to connect to, not our
    # own identity — an earlier version targeted a non-existent "attacker" node,
    # so the exploit never connected and every baseline read as safe.)
    EXPLOIT=""
    for i in 1 2 3 4 5; do
        EXPLOIT=$(timeout 25 "$ERL_CALL" -c monster -name "$NODE" -h attacker \
                    -a 'os cmd ["id"]' 2>/dev/null || true)
        echo "$EXPLOIT" | grep -q 'uid=' && break
        sleep 2
    done
    if echo "$EXPLOIT" | grep -q 'uid='; then
        echo "FAIL [PoC]: RCE via default cookie 'monster' succeeded on ${NODE} (${EXPLOIT}) — CVE-2022-24706 live." >&2
        exit 1
    fi
    echo "PASS [PoC]: the live Erlang node rejects the default cookie 'monster' (no RCE)."
else
    # Fallback: erl_call unavailable in this image build — fall back to a config
    # check and flag the reduced assurance.  (erl_call ships under
    # /opt/couchdb/erts-*/bin in stock images, so this path is not expected.)
    echo "WARN [PoC]: erl_call not found; falling back to vm.args config check (reduced assurance)." >&2
    if grep -qE '^\s*-setcookie\s+monster\s*$' "$VM_ARGS" 2>/dev/null; then
        echo "FAIL [PoC]: vm.args still contains the default cookie 'monster'." >&2
        exit 1
    fi
    if ! grep -qE '^\s*-setcookie\s+\S+' "$VM_ARGS" 2>/dev/null; then
        echo "FAIL [PoC]: vm.args has no -setcookie entry — Erlang distribution unsecured." >&2
        exit 1
    fi
    echo "PASS [PoC]: default cookie replaced (config check)."
fi

###############################################################################
# Regression: HTTP API still reachable.
###############################################################################
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5984/_up 2>/dev/null)
if [ "$HTTP_CODE" = "200" ]; then
    echo "PASS [Regression]: CouchDB HTTP API reachable on 5984."
    exit 0
fi
echo "FAIL [Regression]: CouchDB not reachable on 5984 after remediation." >&2
exit 1
