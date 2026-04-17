#!/bin/bash
# Scenario 54: BIND 9.18 — Open Recursive Resolver (misconfig)
set -u

###############################################################################
# PoC: External recursive query must be refused
###############################################################################

RESULT=$(dig +short @127.0.0.1 google.com A 2>/dev/null)
STATUS=$(dig @127.0.0.1 google.com A 2>/dev/null | grep -c 'REFUSED' || true)

if [ "$STATUS" -gt 0 ]; then
    echo "PASS [PoC]: External recursive query returns REFUSED."
else
    echo "FAIL [PoC]: Server still resolves external queries (open recursion active)." >&2
    exit 1
fi

###############################################################################
# Config check: allow-recursion must not contain 'any'
###############################################################################

if grep -r 'allow-recursion' /etc/bind/ 2>/dev/null | grep -q '\bany\b'; then
    echo "FAIL [PoC]: named.conf still contains allow-recursion { any; }." >&2
    exit 1
fi
echo "PASS [PoC]: allow-recursion does not permit 'any'."

###############################################################################
# Regression: local.test A record must still resolve
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
