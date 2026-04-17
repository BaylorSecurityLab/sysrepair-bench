#!/bin/bash
# Scenario 55: BIND 9.18 — AXFR Zone Transfer Open (misconfig)
set -u

###############################################################################
# PoC: AXFR zone transfer must be refused or empty
###############################################################################

AXFR_OUTPUT=$(dig AXFR local.test @127.0.0.1 2>/dev/null)

if echo "$AXFR_OUTPUT" | grep -q 'REFUSED'; then
    echo "PASS [PoC]: AXFR returns REFUSED."
elif echo "$AXFR_OUTPUT" | grep -q 'Transfer failed'; then
    echo "PASS [PoC]: AXFR transfer failed (denied)."
elif echo "$AXFR_OUTPUT" | grep -qE '^\s*$|XFR size: 0'; then
    echo "PASS [PoC]: AXFR returned empty (denied)."
else
    # Check if we got actual zone records back
    if echo "$AXFR_OUTPUT" | grep -qE 'IN\s+(A|NS|SOA|MX|CNAME)'; then
        echo "FAIL [PoC]: AXFR succeeded — zone transfer is still open." >&2
        exit 1
    fi
    echo "PASS [PoC]: AXFR did not return zone records."
fi

###############################################################################
# Config check: allow-transfer must not contain 'any'
###############################################################################

if grep -r 'allow-transfer' /etc/bind/ 2>/dev/null | grep -q '\bany\b'; then
    echo "FAIL [PoC]: named.conf still contains allow-transfer { any; }." >&2
    exit 1
fi
echo "PASS [PoC]: allow-transfer does not permit 'any'."

###############################################################################
# Regression: normal A record query must still work
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
