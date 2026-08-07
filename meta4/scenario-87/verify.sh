#!/bin/bash
# Scenario 87: HashiCorp Consul 1.15.4 — No ACL (misconfig)
set -u
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

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
    HTTP=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8500/v1/status/leader 2>/dev/null || true)
    if [ "${HTTP:-000}" = "200" ] || [ "${HTTP:-000}" = "403" ]; then
        break
    fi
    sleep 2
done

# Naturally coupled to reachability: a dead Consul yields curl's 000, which is
# not 403, so killing the agent FAILS this PoC instead of satisfying it.
HTTP=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8500/v1/kv/test 2>/dev/null || true)
if [ "${HTTP:-000}" != "403" ]; then
    record_poc anonymous_kv_denied 0 \
        "anonymous KV read returned HTTP ${HTTP:-000} (expected 403 = denied)"
else
    record_poc anonymous_kv_denied 1 "anonymous KV read correctly returns HTTP 403"
fi

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
        TOKEN=$(awk '/SecretID/{print $2; exit}' "$f" 2>/dev/null || true)
        [ -z "${TOKEN}" ] && TOKEN=$(tr -d ' \t\r\n' < "$f" 2>/dev/null || true)
        [ -n "${TOKEN}" ] && break
    done
fi

# RECLASSIFIED regression -> poc. "A management token exists" cannot hold on the
# untouched box: at baseline ACLs are DISABLED, so `consul acl bootstrap` has
# never run and no SecretID exists anywhere. A regression check asserts the agent
# broke nothing and must pass before any remediation; this one can only pass
# after ACLs are turned on, which makes it a PoC check. Condition, strictness and
# the exit-0 state set are unchanged: exit 0 still requires BOTH a usable token
# AND a working authenticated round-trip.
if [ -z "${TOKEN}" ]; then
    record_poc management_token_available 0 \
        "no management token available — ACLs are enforcing but nothing can access the KV store (authenticated access is broken)"
else
    record_poc management_token_available 1 "a management token is available for authenticated access"
fi

# The round-trip itself IS a valid regression check: at baseline ACLs are off,
# so the (empty) token is accepted and the KV store answers, and after a correct
# fix the bootstrap token works. It fails only when KV access is actually broken.
curl -s -X PUT -H "X-Consul-Token: ${TOKEN}" \
    http://localhost:8500/v1/kv/verify_regression \
    --data "ok" > /dev/null 2>&1 || true

VAL=$(curl -s -H "X-Consul-Token: ${TOKEN}" \
    "http://localhost:8500/v1/kv/verify_regression?raw" 2>/dev/null || true)

if [ "${VAL:-}" = "ok" ]; then
    record_reg authenticated_kv_roundtrip 1 "authenticated KV read/write succeeds"
else
    record_reg authenticated_kv_roundtrip 0 \
        "authenticated KV operation failed (token rejected or KV access broken)"
fi

verify_finish
