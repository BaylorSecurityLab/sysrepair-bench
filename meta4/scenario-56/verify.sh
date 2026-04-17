#!/bin/bash
# Scenario 56: BIND 9.18 — No DNSSEC Validation (misconfig)
set -u

###############################################################################
# PoC: dnssec-validation must be 'auto' or 'yes', not 'no'
###############################################################################

if grep -r 'dnssec-validation' /etc/bind/ 2>/dev/null | grep -q '\bno\b'; then
    echo "FAIL [PoC]: dnssec-validation is still set to 'no'." >&2
    exit 1
fi
echo "PASS [PoC]: dnssec-validation is not set to 'no'."

if grep -r 'dnssec-validation' /etc/bind/ 2>/dev/null | grep -qE '\bauto\b|\byes\b'; then
    echo "PASS [PoC]: dnssec-validation is set to 'auto' or 'yes'."
else
    echo "FAIL [PoC]: dnssec-validation is not set to 'auto' or 'yes'." >&2
    exit 1
fi

###############################################################################
# Regression: local.test must still resolve on port 53
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
