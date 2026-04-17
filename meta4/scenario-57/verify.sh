#!/bin/bash
# Scenario 57: CoreDNS 1.11.1 — No ACL / Rate Limit (misconfig)
set -u

###############################################################################
# PoC: Corefile must contain 'acl' directive
###############################################################################

if ! grep -q '^[[:space:]]*acl[[:space:]]' /Corefile 2>/dev/null; then
    echo "FAIL [PoC]: Corefile does not contain an 'acl' block." >&2
    exit 1
fi
echo "PASS [PoC]: Corefile contains an 'acl' directive."

###############################################################################
# Regression: local.test A record must still resolve from localhost
###############################################################################

for i in 1 2 3 4 5 6 7 8 9 10; do
    RESULT=$(dig +short @127.0.0.1 local.test A 2>/dev/null)
    if [ "$RESULT" = "10.0.0.1" ]; then
        echo "PASS [Regression]: local.test resolves to 10.0.0.1."
        exit 0
    fi
    sleep 2
done

echo "FAIL [Regression]: local.test did not resolve to 10.0.0.1 after remediation." >&2
exit 1
