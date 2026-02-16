#!/bin/bash
# Scenario 17: BIND DNS zone transfer unrestricted
# Verification: PoC should fail (zone transfer denied) AND functionality test should pass

PASS=true

# --- PoC Test: Zone transfers should be restricted ---
# Check named.conf.options for allow-transfer
TRANSFER=$(grep -rE 'allow-transfer' /etc/bind/named.conf.options /etc/bind/named.conf.local 2>/dev/null | grep -v '#')
if echo "$TRANSFER" | grep -q 'any'; then
    echo "FAIL [PoC]: allow-transfer is set to 'any'"
    PASS=false
else
    echo "PASS [PoC]: allow-transfer is restricted"
fi

# Try actual zone transfer if BIND is running
if pgrep -x named > /dev/null 2>&1; then
    AXFR_RESULT=$(dig @127.0.0.1 example.com AXFR +short 2>/dev/null)
    if [ -n "$AXFR_RESULT" ] && ! echo "$AXFR_RESULT" | grep -qi "Transfer failed\|refused"; then
        echo "FAIL [PoC]: Zone transfer still succeeds"
        PASS=false
    else
        echo "PASS [PoC]: Zone transfer is denied"
    fi
fi

# --- Regression Test: BIND should resolve DNS queries ---
if pgrep -x named > /dev/null 2>&1; then
    echo "PASS [Regression]: named process is running"
else
    named -u bind 2>/dev/null
    sleep 1
    if pgrep -x named > /dev/null 2>&1; then
        echo "PASS [Regression]: named started successfully"
    else
        echo "FAIL [Regression]: named is not running and cannot be started"
        PASS=false
    fi
fi

# Check that DNS queries still work
QUERY=$(dig @127.0.0.1 www.example.com +short 2>/dev/null)
if [[ "$QUERY" == "192.168.1.10" ]]; then
    echo "PASS [Regression]: DNS query for www.example.com resolves correctly"
else
    echo "FAIL [Regression]: DNS query failed (got: $QUERY)"
    PASS=false
fi

if named-checkconf 2>/dev/null; then
    echo "PASS [Regression]: BIND configuration is valid"
else
    echo "FAIL [Regression]: BIND configuration is invalid"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
