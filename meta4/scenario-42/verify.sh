#!/bin/bash
# Scenario 42: CouchDB 3.2.1 — Default Erlang Cookie RCE (CVE-2022-24706)
set -u

VM_ARGS="/opt/couchdb/etc/vm.args"

###############################################################################
# PoC: vm.args must NOT contain the default cookie "monster"
###############################################################################

if grep -qE '^\s*-setcookie\s+monster\s*$' "$VM_ARGS" 2>/dev/null; then
    echo "FAIL [PoC]: vm.args still contains the default Erlang cookie 'monster' — CVE-2022-24706 exploitable." >&2
    exit 1
fi

# Also ensure a cookie is set at all (empty or missing cookie is also dangerous)
if ! grep -qE '^\s*-setcookie\s+\S+' "$VM_ARGS" 2>/dev/null; then
    echo "FAIL [PoC]: vm.args has no -setcookie entry — Erlang distribution is unsecured." >&2
    exit 1
fi

echo "PASS [PoC]: Default Erlang cookie 'monster' has been replaced."

###############################################################################
# Regression: CouchDB HTTP API must still respond on 5984
###############################################################################

for i in 1 2 3 4 5; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5984/ 2>/dev/null)
    if [ "$HTTP_CODE" = "200" ]; then
        echo "PASS [Regression]: CouchDB HTTP API reachable on 5984."
        exit 0
    fi
    sleep 2
done

echo "FAIL [Regression]: CouchDB not reachable on 5984 after remediation." >&2
exit 1
