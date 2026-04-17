#!/bin/bash
# Scenario 87: HashiCorp Consul 1.15.4 — No ACL (misconfig)
set -u

###############################################################################
# PoC: anonymous KV request must return 403
###############################################################################

# Wait for Consul to be ready
for i in 1 2 3 4 5 6 7 8 9 10; do
    HTTP=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8500/v1/status/leader 2>/dev/null)
    if [ "${HTTP}" = "200" ]; then
        break
    fi
    sleep 2
done

HTTP=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8500/v1/kv/test 2>/dev/null)
if [ "${HTTP}" != "403" ]; then
    echo "FAIL [PoC]: Anonymous KV read returned HTTP ${HTTP} (expected 403)." >&2
    exit 1
fi
echo "PASS [PoC]: Anonymous KV read correctly returns HTTP 403."

###############################################################################
# Regression: KV operations work with a valid management token
###############################################################################

if [ -z "${CONSUL_HTTP_TOKEN:-}" ]; then
    echo "SKIP [Regression]: CONSUL_HTTP_TOKEN not set — skipping authenticated KV check."
    exit 0
fi

curl -s -X PUT -H "X-Consul-Token: ${CONSUL_HTTP_TOKEN}" \
    http://localhost:8500/v1/kv/verify_regression \
    --data "ok" > /dev/null

VAL=$(curl -s -H "X-Consul-Token: ${CONSUL_HTTP_TOKEN}" \
    http://localhost:8500/v1/kv/verify_regression?raw 2>/dev/null)

if [ "${VAL}" = "ok" ]; then
    echo "PASS [Regression]: Authenticated KV read/write succeeds."
    exit 0
fi

echo "FAIL [Regression]: Authenticated KV operation failed." >&2
exit 1
