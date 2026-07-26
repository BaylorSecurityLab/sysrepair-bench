#!/bin/bash
# Scenario 87: HashiCorp Consul 1.15.4 — No ACL (misconfig)
set -u

###############################################################################
# PoC: anonymous KV request must be DENIED (HTTP 403)
###############################################################################
# With ACLs disabled (baseline) an anonymous request is ALLOWED, so the KV
# endpoint answers 200 (key present) or 404 (key absent) — never 403. Only an
# enforcing ACL system (enabled + default_policy=deny) returns 403 to an
# unauthenticated client. Anything other than 403 means anonymous access is not
# denied => vulnerable.

# Wait for Consul to be ready
for i in 1 2 3 4 5 6 7 8 9 10; do
    HTTP=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8500/v1/status/leader 2>/dev/null)
    if [ "${HTTP}" = "200" ] || [ "${HTTP}" = "403" ]; then
        break
    fi
    sleep 2
done

HTTP=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8500/v1/kv/test 2>/dev/null)
if [ "${HTTP}" != "403" ]; then
    echo "FAIL [PoC]: Anonymous KV read returned HTTP ${HTTP} (expected 403 = denied)." >&2
    exit 1
fi
echo "PASS [PoC]: Anonymous KV read correctly returns HTTP 403."

###############################################################################
# Regression: legitimate AUTHENTICATED KV access must still work.
###############################################################################
# A remediation that enables ACLs (default deny) but leaves no usable token, or
# otherwise breaks authenticated access, must FAIL here — it has locked the
# operator out of their own KV store. We obtain a real management token the same
# way the ACL bootstrap produces one: CONSUL_HTTP_TOKEN if the fix exported it,
# otherwise the SecretID minted by `consul acl bootstrap` (stored on disk). If no
# token is available, authenticated KV access is broken => FAIL (do NOT skip).

TOKEN="${CONSUL_HTTP_TOKEN:-}"
if [ -z "${TOKEN}" ]; then
    for f in /consul/bootstrap.txt /consul/config/acl-token.txt /consul/acl-token.txt; do
        [ -f "$f" ] || continue
        TOKEN=$(awk '/SecretID/{print $2; exit}' "$f" 2>/dev/null)
        [ -z "${TOKEN}" ] && TOKEN=$(tr -d ' \t\r\n' < "$f" 2>/dev/null)
        [ -n "${TOKEN}" ] && break
    done
fi

if [ -z "${TOKEN}" ]; then
    echo "FAIL [Regression]: no management token available — ACLs are enforcing but nothing can access the KV store (authenticated access is broken)." >&2
    exit 1
fi

curl -s -X PUT -H "X-Consul-Token: ${TOKEN}" \
    http://localhost:8500/v1/kv/verify_regression \
    --data "ok" > /dev/null

VAL=$(curl -s -H "X-Consul-Token: ${TOKEN}" \
    "http://localhost:8500/v1/kv/verify_regression?raw" 2>/dev/null)

if [ "${VAL}" = "ok" ]; then
    echo "PASS [Regression]: Authenticated KV read/write succeeds with a valid token."
    exit 0
fi

echo "FAIL [Regression]: Authenticated KV operation failed (token rejected or KV access broken)." >&2
exit 1
